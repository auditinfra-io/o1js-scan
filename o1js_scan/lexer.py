"""o1js / Mina zkApp lexer — application-layer ZK soundness analyzer.

This finds under-constrained *method witnesses* and the o1js-specific
authorization / precondition footguns that break a Mina zkApp's soundness at
the application layer — the analog, for o1js, of under-constrained-signal
scanning for Circom.

Background — why application-layer, not the proving system
----------------------------------------------------------

A Mina zkApp is written in o1js (TypeScript). o1js compiles `@method` bodies
to Kimchi circuits, exactly as Circom compiles templates to R1CS. The bug
classes an *application* auditor finds are NOT in the Kimchi proving system
(that is upstream o1Labs infrastructure) — they are in the zkApp's own
constraints, the same way Circom bugs are in the circuit author's signals, not
in the proving backend. So the analog of "Circom under-constrained-signal
scanning" is "o1js under-constrained-witness / missing-precondition scanning".
That is what this module does.

o1js soundness model (the three footguns this encodes)
------------------------------------------------------

1. **State preconditions.** Reading on-chain state with ``this.x.get()`` does
   NOT bind the proof to the current on-chain value. You must follow it with
   ``this.x.requireEquals(...)`` (or use the combined
   ``this.x.getAndRequireEquals()``). Omitting the precondition lets a prover
   substitute any value for ``x`` — the canonical o1js vulnerability.
   Rule: ``O1JS_MISSING_STATE_PRECONDITION``.

2. **Witness constraints.** A ``@method`` argument is a PRIVATE witness chosen
   by the prover/caller. If it flows into a value-transfer (``this.send``),
   a state write (``this.x.set(arg)``), or an authorization decision without
   being asserted against on-chain state, the prover controls it. This is the
   direct analog of Circom ``UnconstrainedCircuitVariable``.
   Rules: ``O1JS_UNCONSTRAINED_WITNESS`` (never asserted at all) and
   ``O1JS_WITNESS_NOT_BOUND_TO_STATE`` (only trivially asserted, e.g.
   ``> 0`` or against a constant, but never tied to on-chain state).
   The OTHER witness source is ``Provable.witness(Type, () => ...)``: the
   callback runs OUTSIDE the circuit (it is only a hint), so the returned
   value is a FRESH prover-controlled witness carrying no constraint of its
   own. If such a local flows into a send/state effect without being
   re-derived and asserted in-circuit, it is the o1js analog of an
   under-constrained Circom signal.
   Rule: ``O1JS_UNCONSTRAINED_PROVABLE_WITNESS``.
   A witness used ONLY as the ``to:`` recipient of a send is prover-chosen
   by design (a user names their own withdrawal destination), so it is
   reported as a LOW, informational ``O1JS_UNCONSTRAINED_RECIPIENT`` that
   does not fail CI — an ordering comparison or equality against a
   state-derived value (``amount.assertLessThanOrEqual(bal)``, incl. the
   chained ``amount.lessThanOrEqual(bal).assertTrue()`` form) counts as bound.

3. **Stale Merkle roots.** A zkApp that stores off-chain data keeps only the
   Merkle *root* on-chain (a ``@state(Field)``) and takes a witness as a
   ``@method`` argument. A root recomputed from that witness
   (``witness.computeRootAndKey(...)`` / ``witness.calculateRoot(...)``) must
   be bound to the CURRENT on-chain root (``this.root.requireEquals(...)`` /
   ``getAndRequireEquals()`` + ``assertEquals``) before the tree is updated —
   otherwise a prover can supply a witness for a fabricated/stale tree and the
   proof still verifies (forged membership / stale-state replay). A method that
   recomputes a witness root but binds NONE of them to on-chain state is
   flagged. Rule: ``O1JS_STALE_MERKLE_ROOT``.

4. **Permissions & raw-Field amounts.**
   - ``account.permissions.set`` with ``editState`` / ``send`` set to
     ``proofOrSignature()`` or ``none()`` means the zkApp account key can
     bypass the proof logic by signing — defeating the whole circuit.
     Rule: ``O1JS_WEAK_PERMISSIONS``.
   - A raw ``Field`` (NOT ``UInt64``/``UInt32``, which are range-checked by
     construction) used as a transfer amount can exceed the field modulus
     intent / wrap. Rule: ``MissingRangeCheck``.

Lexical, not full TS AST: o1js code is decorator + brace-delimited-method-body
shaped, regex-tractable, and the output is meant to be hand-triaged. Env
kill-switch: ``AUDIT_O1JS_LEXER=0``.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from .vuln import Severity, Vulnerability

# Tier bucket stamped onto every finding this module emits.
O1JS_ORIGIN_TIER = "o1js"


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

# Upper bounds on how much a single regex quantifier will scan. o1js source is
# hand-written and well under these limits; the caps exist purely so a crafted
# or malformed `.ts` file (a giant identifier run, an unclosed literal, a
# minified blob that slips past the node_modules filter) can't drive the
# scanner into O(n^2) backtracking and hang a CI run. See _asserts_on and
# _FUNC_HEAD_RE below.
_MAX_IDENT = 120       # longest identifier a real token would ever be
_MAX_PARAMS = 4000     # longest parameter list / return-type annotation
_MAX_CALL_ARG = 2000   # longest single call-argument expression

_O1JS_IMPORT_RE = re.compile(r"""from\s+['"]o1js['"]""")
_SMARTCONTRACT_RE = re.compile(r"\bclass\s+(\w+)\s+extends\s+SmartContract\b")
_METHOD_DECORATOR_RE = re.compile(
    r"@method(?:\.returns\([^)]{0,%d}\))?\s+(?:async\s+)?(\w+)\s*\(" % _MAX_PARAMS,
)
_STATE_DECL_RE = re.compile(r"@state\(\s*(\w+)\s*\)\s+(\w+)\s*=")
# `const x = Provable.witness(Type, () => ...)` — a fresh in-circuit witness.
# Also covers `witnessFields` and the async `witnessAsync` form.
_PROVABLE_WITNESS_RE = re.compile(
    r"\b(?:const|let|var)\s+(\w{1,%d})\s*=\s*(?:await\s+)?"
    r"Provable\s*\.\s*(witness|witnessFields|witnessAsync)\s*\(" % _MAX_IDENT,
)
# A Merkle root recomputed from a prover-supplied witness.
#   const [computedRoot, key] = witness.computeRootAndKey(value);
_MERKLE_DESTRUCT_RE = re.compile(
    r"(?:const|let|var)\s*\[\s*(\w{1,%d})\s*(?:,[^\]]{0,%d})?\]\s*=\s*"
    r"([\w.]{1,%d})\s*\.\s*(computeRootAndKey|computeRootAndKeyV2)\s*\("
    % (_MAX_IDENT, _MAX_IDENT, _MAX_IDENT),
)
#   const root = witness.calculateRoot(leaf);   (MerkleWitness API — single Field)
_MERKLE_ASSIGN_RE = re.compile(
    r"(?:const|let|var)\s+(\w{1,%d})\s*=\s*([\w.]{1,%d})\s*\.\s*"
    r"(calculateRoot)\s*\(" % (_MAX_IDENT, _MAX_IDENT),
)


def is_o1js_source(content: str, filepath: str = "") -> bool:
    """True if ``content`` is an o1js zkApp file worth analyzing."""
    if filepath and not filepath.endswith((".ts", ".js", ".mjs")):
        return False
    return bool(_O1JS_IMPORT_RE.search(content) and _SMARTCONTRACT_RE.search(content))


# ---------------------------------------------------------------------------
# Comment stripping + brace-balanced method body extraction
# ---------------------------------------------------------------------------

def _strip_comments(src: str) -> str:
    """Length-preserving removal of // and /* */ comments and string bodies
    (so an `assert` inside a string literal can't fool a rule)."""
    out: List[str] = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            end = src.find("\n", i)
            end = n if end == -1 else end
            out.append(" " * (end - i))
            i = end
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            end = src.find("*/", i + 2)
            if end == -1:
                out.append(" " * (n - i))
                break
            out.append(" " * (end + 2 - i))
            i = end + 2
            continue
        if c in ("'", '"', "`"):
            j = i + 1
            while j < n and src[j] != c:
                if src[j] == "\\":
                    j += 1
                j += 1
            # keep quotes, blank the body so identifiers inside don't match
            out.append(c + " " * max(0, j - i - 1) + (c if j < n else ""))
            i = j + 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _line_of(src: str, idx: int) -> int:
    return src.count("\n", 0, idx) + 1


class _Method:
    __slots__ = ("name", "params", "body", "start_line", "is_method_decorated")

    def __init__(self, name, params, body, start_line, is_method_decorated):
        self.name = name
        self.params = params                # List[str] param names
        self.body = body
        self.start_line = start_line
        self.is_method_decorated = is_method_decorated


_FUNC_HEAD_RE = re.compile(
    r"(?P<deco>@method(?:\.returns\([^)]{0,%d}\))?\s+)?"
    r"(?:async\s+)?(?P<name>\w{1,%d})\s*\((?P<params>[^)]{0,%d})\)\s*"
    r"(?::\s*[^{]{1,%d})?\{" % (_MAX_PARAMS, _MAX_IDENT, _MAX_PARAMS, _MAX_PARAMS),
)


def _extract_methods(stripped: str, full_src: str) -> List[_Method]:
    """Brace-balanced extraction of every method-like body in the contract,
    flagging which carry the ``@method`` decorator."""
    methods: List[_Method] = []
    for m in _FUNC_HEAD_RE.finditer(stripped):
        name = m.group("name")
        if name in ("if", "for", "while", "switch", "catch", "function"):
            continue
        params_raw = m.group("params")
        param_names = _parse_param_names(params_raw)
        open_idx = m.end() - 1
        depth = 1
        i = open_idx + 1
        n = len(stripped)
        while i < n and depth:
            ch = stripped[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            i += 1
        body = stripped[open_idx + 1: i - 1]
        methods.append(_Method(
            name=name,
            params=param_names,
            body=body,
            start_line=_line_of(full_src, m.start()),
            is_method_decorated=bool(m.group("deco")),
        ))
    return methods


def _parse_param_names(params_raw: str) -> List[str]:
    """`a: Field, b: PublicKey` -> ['a', 'b'] (depth-aware on <> and ())."""
    out: List[str] = []
    depth = 0
    cur = []
    for ch in params_raw:
        if ch in "<([{":
            depth += 1
        elif ch in ">)]}":
            depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if cur:
        out.append("".join(cur))
    names: List[str] = []
    for raw in out:
        raw = raw.strip()
        if not raw:
            continue
        # strip default values
        raw = raw.split("=")[0]
        # `name: Type` -> name
        name = raw.split(":")[0].strip().lstrip(".")  # handle rest/spread
        name = re.sub(r"^\{.*\}$", "", name)  # skip destructured params
        if re.fullmatch(r"\w+", name):
            names.append(name)
    return names


# ---------------------------------------------------------------------------
# State-field map (name -> declared o1js type)
# ---------------------------------------------------------------------------

def _state_fields(stripped: str) -> Dict[str, str]:
    return {m.group(2): m.group(1) for m in _STATE_DECL_RE.finditer(stripped)}


# ---------------------------------------------------------------------------
# Inline suppressions
# ---------------------------------------------------------------------------
#
# Let a reviewer silence a finding they've triaged, without the all-or-nothing
# env kill-switch:
#
#     this.send({ to, amount });  // o1js-scan-disable-line O1JS_UNCONSTRAINED_WITNESS
#
#     // o1js-scan-disable-next-line
#     this.send({ to, amount });
#
# A bare directive (no rule ids) suppresses every rule on the target line;
# otherwise only the listed rule ids (space/comma separated) are suppressed.
_SUPPRESS_RE = re.compile(r"//\s*o1js-scan-disable(-next)?-line\b([^\n]*)")


def _suppressions(content: str) -> Dict[int, Set[str]]:
    """Map target line number -> set of suppressed rule ids ({"*"} = all)."""
    out: Dict[int, Set[str]] = {}
    for m in _SUPPRESS_RE.finditer(content):
        line = content.count("\n", 0, m.start()) + 1
        target = line + 1 if m.group(1) else line
        rules = {r for r in re.split(r"[\s,]+", m.group(2).strip()) if r} or {"*"}
        out.setdefault(target, set()).update(rules)
    return out


def _apply_suppressions(content: str, vulns: List[Vulnerability]) -> List[Vulnerability]:
    supp = _suppressions(content)
    if not supp:
        return vulns
    kept: List[Vulnerability] = []
    for v in vulns:
        ln = v.location[0] if v.location else 0
        rules = supp.get(ln)
        if rules and ("*" in rules or v.rule_id in rules):
            continue
        kept.append(v)
    return kept


# ---------------------------------------------------------------------------
# Lexer
# ---------------------------------------------------------------------------

class O1jsLexer:
    """Semantic analyzer for o1js zkApp source."""

    def analyze(self, content: str, file_path: Optional[Path] = None) -> List[Vulnerability]:
        if os.environ.get("AUDIT_O1JS_LEXER", "1") == "0":
            return []
        if not is_o1js_source(content, str(file_path or "")):
            return []

        stripped = _strip_comments(content)
        state = _state_fields(stripped)
        methods = _extract_methods(stripped, content)

        vulns: List[Vulnerability] = []
        vulns += self._detect_missing_state_precondition(content, stripped, methods, state)
        vulns += self._detect_unconstrained_witness(content, methods, state)
        vulns += self._detect_unconstrained_provable_witness(content, methods, state)
        vulns += self._detect_stale_merkle_root(content, methods, state)
        vulns += self._detect_raw_field_amount(content, methods)
        vulns += self._detect_weak_permissions(content, stripped)
        return _apply_suppressions(content, vulns)

    # --- Rule 1: state read without precondition --------------------------

    def _detect_missing_state_precondition(
        self, src: str, stripped: str, methods: List[_Method], state: Dict[str, str],
    ) -> List[Vulnerability]:
        out: List[Vulnerability] = []
        for meth in methods:
            body = meth.body
            for field_name in state:
                # `this.<field>.get()` reads
                get_re = re.compile(
                    r"this\s*\.\s*" + re.escape(field_name) + r"\s*\.\s*get\s*\(\s*\)"
                )
                if not get_re.search(body):
                    continue
                # precondition forms that make the read sound:
                #   this.<field>.getAndRequireEquals()
                #   this.<field>.requireEquals(...)
                #   this.<field>.assertEquals(...)   (older o1js)
                safe = re.search(
                    r"this\s*\.\s*" + re.escape(field_name)
                    + r"\s*\.\s*(getAndRequireEquals|requireEquals|assertEquals)\s*\(",
                    body,
                )
                # also accept getAndRequireEquals used INSTEAD of get (no bare get)
                only_safe_form = re.search(
                    r"this\s*\.\s*" + re.escape(field_name) + r"\s*\.\s*getAndRequireEquals",
                    body,
                )
                if safe or only_safe_form:
                    continue
                # locate the offending line
                rel = get_re.search(body)
                line = meth.start_line + body.count("\n", 0, rel.start())
                out.append(Vulnerability(
                    pattern_name="O1JS_MISSING_STATE_PRECONDITION",
                    severity=Severity.HIGH,
                    function=meth.name,
                    location=(line, 0),
                    origin_tier=O1JS_ORIGIN_TIER,
                    rule_id="O1JS_MISSING_STATE_PRECONDITION",
                    title=f"State `{field_name}` read without precondition in `{meth.name}`",
                    description=(
                        f"`this.{field_name}.get()` is read in `{meth.name}` without a "
                        f"matching `requireEquals(...)` / `getAndRequireEquals()`. In o1js "
                        f"a bare `get()` adds NO account precondition, so the proof does not "
                        f"bind `{field_name}` to its on-chain value — a prover can substitute "
                        f"any value. Use `this.{field_name}.getAndRequireEquals()`."
                    ),
                    evidence={
                        "state_field": field_name,
                        "method": meth.name,
                        "framework": "o1js",
                    },
                ))
        return out

    # --- Rules 2/2b: under-constrained method witnesses -------------------

    def _detect_unconstrained_witness(
        self, src: str, methods: List[_Method], state: Dict[str, str],
    ) -> List[Vulnerability]:
        out: List[Vulnerability] = []
        for meth in methods:
            if not meth.is_method_decorated:
                continue  # only @method args are prover-controlled witnesses
            body = meth.body
            # A method that calls `this.requireSignature()` is admin/owner-gated:
            # its arguments are chosen by the key holder, NOT by an arbitrary
            # prover, so they are not attacker-controlled witnesses. (Same role
            # as `onlyOwner` for the Solidity detectors.) Skip such methods.
            if _method_is_signature_gated(body):
                continue
            # variables that ARE bound to on-chain state in this body:
            # locals assigned from this.<state>.getAndRequireEquals()/get()
            state_bound: Set[str] = set()
            for am in re.finditer(
                r"\b(?:const|let|var)\s+(\w+)\s*=\s*this\s*\.\s*(\w+)\s*\.\s*"
                r"(?:getAndRequireEquals|get)\s*\(", body,
            ):
                if am.group(2) in state:
                    state_bound.add(am.group(1))

            for arg in meth.params:
                effect = self._witness_effect(body, arg)
                if effect is None:
                    continue  # arg not used in any state-changing effect → ignore
                asserts = self._asserts_on(body, arg, state_bound)
                if asserts == "bound":
                    continue  # tied to on-chain state / signature → sound
                kind = effect[0]
                line = meth.start_line + body.count("\n", 0, effect[1])
                if kind == "send_recipient":
                    # A caller choosing their own send destination is by design for
                    # user-initiated withdrawals; recipients are not meant to be
                    # bound to on-chain state. Report as LOW/informational only —
                    # it matters only when the destination should be fixed.
                    out.append(Vulnerability(
                        pattern_name="O1JS_UNCONSTRAINED_RECIPIENT",
                        severity=Severity.LOW,
                        function=meth.name,
                        location=(line, 0),
                        origin_tier=O1JS_ORIGIN_TIER,
                        rule_id="O1JS_UNCONSTRAINED_RECIPIENT",
                        title=f"Recipient `{arg}` is prover-chosen in `{meth.name}`",
                        description=(
                            f"`{arg}` is the `to:` recipient of a `this.send(...)` in "
                            f"`{meth.name}` and is a prover-chosen `@method` argument. This "
                            f"is usually INTENDED — a user initiating a withdrawal names "
                            f"their own destination. It only matters if the destination is "
                            f"meant to be constrained (e.g. a fixed treasury or an address "
                            f"recorded in on-chain state); in that case bind `{arg}` with "
                            f"`assertEquals(...)` against that state. Otherwise informational."
                        ),
                        evidence={
                            "witness": arg, "method": meth.name,
                            "effect": kind, "effect_expr": effect[2],
                            "framework": "o1js",
                        },
                    ))
                    continue
                if asserts == "none":
                    out.append(Vulnerability(
                        pattern_name="O1JS_UNCONSTRAINED_WITNESS",
                        severity=Severity.HIGH if kind == "send_amount" else Severity.MEDIUM,
                        function=meth.name,
                        location=(line, 0),
                        origin_tier=O1JS_ORIGIN_TIER,
                        rule_id="O1JS_UNCONSTRAINED_WITNESS",
                        title=(
                            f"Unconstrained witness `{arg}` flows to {effect[0]} in "
                            f"`{meth.name}`"
                        ),
                        description=(
                            f"`{arg}` is a `@method` argument (a prover-controlled private "
                            f"witness) used in `{effect[0]}` ({effect[2]}) but is never "
                            f"constrained by any `assert*`/`requireEquals`. The prover can "
                            f"choose any value. Direct analog of an under-constrained Circom "
                            f"signal. Bind `{arg}` to on-chain state or a verified signature "
                            f"before using it."
                        ),
                        evidence={
                            "witness": arg, "method": meth.name,
                            "effect": effect[0], "effect_expr": effect[2],
                            "framework": "o1js",
                        },
                    ))
                else:  # "trivial" — asserted but not against state
                    out.append(Vulnerability(
                        pattern_name="O1JS_WITNESS_NOT_BOUND_TO_STATE",
                        severity=Severity.MEDIUM,
                        function=meth.name,
                        location=(line, 0),
                        origin_tier=O1JS_ORIGIN_TIER,
                        rule_id="O1JS_WITNESS_NOT_BOUND_TO_STATE",
                        title=(
                            f"Witness `{arg}` only trivially constrained before {effect[0]} "
                            f"in `{meth.name}`"
                        ),
                        description=(
                            f"`{arg}` flows to `{effect[0]}` ({effect[2]}) with only a trivial "
                            f"constraint (e.g. `> 0` / `!= 0`); it is never bound to on-chain "
                            f"state. For a value-transfer this means the amount/target is not "
                            f"tied to any escrowed/recorded value — confirm the off-chain "
                            f"orchestration makes this safe (atomic deposit+settle), otherwise "
                            f"the contract balance is drainable up to its standing balance."
                        ),
                        evidence={
                            "witness": arg, "method": meth.name,
                            "effect": effect[0], "effect_expr": effect[2],
                            "framework": "o1js",
                        },
                    ))
        return out

    # --- Rule 2c: unconstrained `Provable.witness` locals -----------------

    def _detect_unconstrained_provable_witness(
        self, src: str, methods: List[_Method], state: Dict[str, str],
    ) -> List[Vulnerability]:
        """Flag a ``Provable.witness(...)`` local that flows into a send/state
        effect without ever being asserted. The witness callback runs OUTSIDE
        the circuit, so the returned value is a fresh prover-controlled witness
        — the o1js analog of an under-constrained Circom signal. Reuses the
        effect + assertion machinery from rule 2; any assertion mentioning the
        witness (even a re-derivation check) suppresses, keeping precision high
        (we would rather miss a case than flag correctly-constrained code)."""
        out: List[Vulnerability] = []
        for meth in methods:
            body = meth.body
            # signature-gated methods take key-holder-chosen inputs, not
            # arbitrary-prover witnesses (same carve-out as rule 2).
            if _method_is_signature_gated(body):
                continue
            # locals bound to on-chain state in this body (for _asserts_on).
            state_bound: Set[str] = set()
            for am in re.finditer(
                r"\b(?:const|let|var)\s+(\w+)\s*=\s*this\s*\.\s*(\w+)\s*\.\s*"
                r"(?:getAndRequireEquals|get)\s*\(", body,
            ):
                if am.group(2) in state:
                    state_bound.add(am.group(1))

            for wm in _PROVABLE_WITNESS_RE.finditer(body):
                name, api = wm.group(1), wm.group(2)
                effect = self._witness_effect(body, name)
                if effect is None:
                    continue  # witness never reaches a state-changing effect
                if self._asserts_on(body, name, state_bound) != "none":
                    continue  # constrained in-circuit somehow → sound; skip
                kind = effect[0]
                line = meth.start_line + body.count("\n", 0, effect[1])
                sev = {
                    "send_amount": Severity.HIGH,
                    "state_set": Severity.MEDIUM,
                    "send_recipient": Severity.LOW,
                }.get(kind, Severity.MEDIUM)
                out.append(Vulnerability(
                    pattern_name="O1JS_UNCONSTRAINED_PROVABLE_WITNESS",
                    severity=sev,
                    function=meth.name,
                    location=(line, 0),
                    origin_tier=O1JS_ORIGIN_TIER,
                    rule_id="O1JS_UNCONSTRAINED_PROVABLE_WITNESS",
                    title=(
                        f"Unconstrained `Provable.{api}` result `{name}` flows to "
                        f"{kind} in `{meth.name}`"
                    ),
                    description=(
                        f"`{name}` is produced by `Provable.{api}(...)`, a FRESH in-circuit "
                        f"witness. Its callback runs OUTSIDE the circuit (it is only a prover "
                        f"hint), so `{name}` carries no constraint on its own and is fully "
                        f"prover-controlled. It flows to `{kind}` ({effect[2]}) without any "
                        f"`assert*`/`requireEquals` tying it down, so the prover can substitute "
                        f"any value — the o1js form of an under-constrained Circom signal. A "
                        f"witness must be re-derived and asserted in-circuit (e.g. "
                        f"`{name}.assertEquals(<recomputed>)`) or bound to on-chain state."
                    ),
                    evidence={
                        "witness": name,
                        "witness_source": f"Provable.{api}",
                        "method": meth.name,
                        "effect": kind,
                        "effect_expr": effect[2],
                        "framework": "o1js",
                    },
                ))
        return out

    # --- Rule 3b: stale Merkle root (witness root not bound to state) -----

    def _detect_stale_merkle_root(
        self, src: str, methods: List[_Method], state: Dict[str, str],
    ) -> List[Vulnerability]:
        """Flag a method that recomputes a Merkle root from a prover-supplied
        witness but binds NONE of the recomputed roots to the current on-chain
        root. Per-method (not per-root) on purpose: a correct tree update legitimately
        leaves the NEW root unasserted (it is what gets ``set``), so the soundness
        requirement is that at least one witness-derived root is tied to the
        current on-chain state — proving the witness matches the live tree."""
        if not state:
            return []
        out: List[Vulnerability] = []
        for meth in methods:
            body = meth.body
            # admin/owner-gated methods take a trusted key-holder's witness
            # (same carve-out as the witness rules) — a stale witness is then
            # the signer's own problem, not an attacker's.
            if _method_is_signature_gated(body):
                continue
            roots: List[Tuple[str, str, str, int]] = []  # (root_var, recv, api, offset)
            for m in _MERKLE_DESTRUCT_RE.finditer(body):
                roots.append((m.group(1), m.group(2), m.group(3), m.start()))
            for m in _MERKLE_ASSIGN_RE.finditer(body):
                roots.append((m.group(1), m.group(2), m.group(3), m.start()))
            if not roots:
                continue
            # Relevance gate: the method must actually touch an on-chain state
            # field (read or set), else it is a pure off-chain computation.
            if not any(
                re.search(r"this\s*\.\s*" + re.escape(f) + r"\b", body) for f in state
            ):
                continue
            state_bound: Set[str] = set()
            for am in re.finditer(
                r"\b(?:const|let|var)\s+(\w+)\s*=\s*this\s*\.\s*(\w+)\s*\.\s*"
                r"(?:getAndRequireEquals|get)\s*\(", body,
            ):
                if am.group(2) in state:
                    state_bound.add(am.group(1))

            if any(self._merkle_root_bound(body, rv, state, state_bound)
                   for rv, _, _, _ in roots):
                continue  # at least one recomputed root is tied to the live tree
            root_var, recv, api, off = roots[0]
            line = meth.start_line + body.count("\n", 0, off)
            out.append(Vulnerability(
                pattern_name="O1JS_STALE_MERKLE_ROOT",
                severity=Severity.HIGH,
                function=meth.name,
                location=(line, 0),
                origin_tier=O1JS_ORIGIN_TIER,
                rule_id="O1JS_STALE_MERKLE_ROOT",
                title=(
                    f"Merkle root recomputed from witness `{recv}` is not bound to "
                    f"on-chain state in `{meth.name}`"
                ),
                description=(
                    f"`{meth.name}` recomputes a Merkle root from the prover-supplied "
                    f"witness `{recv}` (`{recv}.{api}(...)`) but never binds a recomputed "
                    f"root to the current on-chain root (no `this.<root>.requireEquals(...)` "
                    f"or `assertEquals` against a `getAndRequireEquals()`-derived value). "
                    f"Without that binding the proof does not check the witness against the "
                    f"LIVE tree, so a prover can supply a witness for a fabricated or stale "
                    f"tree — forging membership or replaying old state. Read the on-chain "
                    f"root with `getAndRequireEquals()` and assert the recomputed root "
                    f"against it before updating."
                ),
                evidence={
                    "root_var": root_var,
                    "witness_recv": recv,
                    "api": api,
                    "method": meth.name,
                    "framework": "o1js",
                },
            ))
        return out

    @staticmethod
    def _merkle_root_bound(
        body: str, root_var: str, state: Dict[str, str], state_bound: Set[str],
    ) -> bool:
        """True if ``root_var`` is asserted against on-chain-state-derived data."""
        rv = re.escape(root_var)

        def _state_derived(expr: str) -> bool:
            if "getAndRequireEquals" in expr or ".get()" in expr:
                return True
            if any(re.search(r"\b" + re.escape(sb) + r"\b", expr) for sb in state_bound):
                return True
            for fm in re.finditer(r"this\s*\.\s*(\w+)\b", expr):
                if fm.group(1) in state:
                    return True
            return False

        # Form A: this.<stateRoot>.requireEquals|assertEquals(... root_var ...)
        for m in re.finditer(
            r"this\s*\.\s*(\w+)\s*\.\s*(?:requireEquals|assertEquals)\s*\(([^;]{0,%d}?)\)"
            % _MAX_CALL_ARG, body,
        ):
            if m.group(1) in state and re.search(r"\b" + rv + r"\b", m.group(2)):
                return True
        # Form B: X.assertEquals|requireEquals(Y) with one side root_var, other state-derived
        for m in re.finditer(
            r"([\w.()]{1,%d})\s*\.\s*(?:assertEquals|requireEquals)\s*\(([^;]{0,%d}?)\)"
            % (_MAX_IDENT, _MAX_CALL_ARG), body,
        ):
            recv, inner = m.group(1), m.group(2)
            in_recv = bool(re.search(r"\b" + rv + r"\b", recv))
            in_inner = bool(re.search(r"\b" + rv + r"\b", inner))
            if not (in_recv or in_inner):
                continue
            other = inner if in_recv else recv
            if _state_derived(other):
                return True
        return False

    @staticmethod
    def _witness_effect(body: str, arg: str) -> Optional[Tuple[str, int, str]]:
        """Return (effect_kind, offset, expr) if ``arg`` flows into a
        state-changing effect. Effect kinds:
          * ``send_amount``    — arg appears in the ``amount:`` value of a send
          * ``send_recipient`` — arg appears ONLY in the ``to:`` value of a send
          * ``state_set``      — arg flows into a ``this.<state>.set(...)``
        A witness that appears in both ``amount`` and ``to`` is ``send_amount``
        (the higher-severity effect wins)."""
        a = re.escape(arg)
        # this.send({ ..., amount: <arg...> }) or this.send({to: <arg...>})
        for sm in re.finditer(r"this\s*\.\s*send\s*\(", body):
            # grab the argument object up to matching )
            seg = _paren_segment(body, sm.end() - 1)
            if not re.search(r"\b" + a + r"\b", seg):
                continue
            keys = _send_object_keys(seg, arg)
            if keys is not None and "amount" not in keys and "to" in keys:
                kind = "send_recipient"
            else:
                # amount value, both, a positional send, or some other key:
                # treat as the amount-flow (higher severity) conservatively.
                kind = "send_amount"
            return (kind, sm.start(), seg.strip()[:80])
        # this.<state>.set(<arg ...>)
        for sm in re.finditer(r"this\s*\.\s*\w+\s*\.\s*set\s*\(", body):
            seg = _paren_segment(body, sm.end() - 1)
            if re.search(r"\b" + a + r"\b", seg):
                return ("state_set", sm.start(), seg.strip()[:80])
        return None

    @staticmethod
    def _asserts_on(body: str, arg: str, state_bound: Set[str]) -> str:
        """Classify how ``arg`` is constrained: 'bound' (tied to on-chain
        state / signature), 'trivial' (only >0 / !=0 / boolean), or 'none'."""
        a = re.escape(arg)
        # collect every assert*/requireEquals expression that mentions arg
        bound = False
        trivial = False
        any_assert = False

        def _state_derived(other: str) -> bool:
            """True if ``other`` references an on-chain-state-derived value."""
            return (any(re.search(r"\b" + re.escape(sb) + r"\b", other) for sb in state_bound)
                    or "getAndRequireEquals" in other or ".get()" in other)

        # Equality AND ordering comparisons all bind the witness when the other
        # operand is state-derived: `amount.assertLessThanOrEqual(bal)` is the
        # idiomatic correct way to bound a withdrawal, not a trivial constraint.
        _state_bindable = (
            "assertEquals", "requireEquals",
            "assertLessThan", "assertLessThanOrEqual",
            "assertGreaterThan", "assertGreaterThanOrEqual",
        )
        # X.assertEquals(Y) / X.assertLessThanOrEqual(Y) where X or Y is arg
        for am in re.finditer(
            r"(\w[\w.()]{0,%d})\s*\.\s*(assertEquals|requireEquals|assertGreaterThan"
            r"|assertGreaterThanOrEqual|assertLessThan|assertLessThanOrEqual"
            r"|assertNotEquals|assertBool|assertTrue|assertFalse)\s*\(([^;]{0,%d}?)\)"
            % (_MAX_IDENT, _MAX_CALL_ARG),
            body,
        ):
            recv, kind, inner = am.group(1), am.group(2), am.group(3)
            mentions = bool(re.search(r"\b" + a + r"\b", recv) or re.search(r"\b" + a + r"\b", inner))
            if not mentions:
                continue
            any_assert = True
            if kind in _state_bindable:
                # bound if the OTHER side references on-chain-state-derived var
                other = inner if re.search(r"\b" + a + r"\b", recv) else recv
                if _state_derived(other):
                    bound = True
                else:
                    trivial = True
            else:
                trivial = True
        # also: equality the other direction `configuredX.assertEquals(arg)`
        for am in re.finditer(
            r"(\w{1,%d})\s*\.\s*(assertEquals|requireEquals)\s*\(\s*" % _MAX_IDENT
            + a + r"\s*\)", body,
        ):
            if am.group(1) in state_bound:
                bound = True
            any_assert = True
        # chained-comparison idiom: `amount.lessThanOrEqual(bal).assertTrue()`
        for cm in re.finditer(
            r"\b" + a + r"\s*\.\s*(?:lessThan|lessThanOrEqual|greaterThan"
            r"|greaterThanOrEqual)\s*\(([^;]{0,%d}?)\)\s*\.\s*assertTrue\s*\(" % _MAX_CALL_ARG,
            body,
        ):
            any_assert = True
            if _state_derived(cm.group(1)):
                bound = True
            else:
                trivial = True
        if bound:
            return "bound"
        if trivial or any_assert:
            return "trivial"
        return "none"

    # --- Rule 3: raw Field used as transfer amount ------------------------

    def _detect_raw_field_amount(
        self, src: str, methods: List[_Method],
    ) -> List[Vulnerability]:
        out: List[Vulnerability] = []
        for meth in methods:
            if not meth.is_method_decorated:
                continue
            # params typed as raw Field (not UInt64/UInt32)
            field_params = set(re.findall(r"(\w+)\s*:\s*Field\b", _method_param_blob(src, meth)))
            for fp in field_params:
                eff = self._witness_effect(meth.body, fp)
                if eff and eff[0] == "send_amount":
                    line = meth.start_line + meth.body.count("\n", 0, eff[1])
                    out.append(Vulnerability(
                        pattern_name="MissingRangeCheck",
                        severity=Severity.HIGH,
                        function=meth.name,
                        location=(line, 0),
                        origin_tier=O1JS_ORIGIN_TIER,
                        rule_id="MissingRangeCheck",
                        title=f"Raw `Field` `{fp}` used as transfer amount in `{meth.name}`",
                        description=(
                            f"`{fp}` is a raw `Field` used as a `send` amount. Unlike "
                            f"`UInt64`/`UInt32` (range-checked by construction), a `Field` is "
                            f"an element mod p and is NOT range-bounded — it can represent a "
                            f"huge/negative-equivalent value. Use `UInt64` for amounts or add "
                            f"an explicit range assertion."
                        ),
                        evidence={"witness": fp, "method": meth.name, "framework": "o1js"},
                    ))
        return out

    # --- Rule 4: weak account permissions ---------------------------------

    def _detect_weak_permissions(self, src: str, stripped: str) -> List[Vulnerability]:
        out: List[Vulnerability] = []
        # find permissions.set({...}) blocks
        for pm in re.finditer(r"permissions\s*\.\s*set\s*\(", stripped):
            seg = _paren_segment(stripped, pm.end() - 1)
            for field in ("editState", "send", "receive", "setDelegate", "incrementNonce"):
                m = re.search(
                    re.escape(field) + r"\s*:\s*Permissions\s*\.\s*(proofOrSignature|none)\s*\(",
                    seg,
                )
                if not m:
                    continue
                weak = m.group(1)
                # editState/send weakened to signature-or-none defeats proof logic
                if field in ("editState", "send") or weak == "none":
                    line = _line_of(src, pm.start())
                    sev = Severity.HIGH if (field in ("editState", "send") and weak == "none") else Severity.MEDIUM
                    out.append(Vulnerability(
                        pattern_name="O1JS_WEAK_PERMISSIONS",
                        severity=sev,
                        function="",
                        location=(line, 0),
                        origin_tier=O1JS_ORIGIN_TIER,
                        rule_id="O1JS_WEAK_PERMISSIONS",
                        title=f"Weak account permission `{field}: Permissions.{weak}()`",
                        description=(
                            f"`{field}` is set to `Permissions.{weak}()`. With "
                            f"`proofOrSignature`, a holder of the zkApp account's private key "
                            f"can change `{field}` by SIGNATURE, bypassing the `@method` proof "
                            f"logic entirely; `none` removes the gate outright. For a zkApp "
                            f"whose security depends on its circuits, `{field}` should be "
                            f"`Permissions.proof()`."
                        ),
                        evidence={"permission": field, "value": weak, "framework": "o1js"},
                    ))
        return out


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

def _method_is_signature_gated(body: str) -> bool:
    """True if a method authorizes via a signature, making its arguments
    key-holder-chosen rather than attacker-controlled.

    Covers the common o1js authorization idioms:
      * ``this.requireSignature()``
      * ``getAndRequireSignature()`` + ``AccountUpdate.createSigned(...)``
      * ``<pubkey>.verify(...)`` over a ``Signature``
    """
    if re.search(r"this\s*\.\s*requireSignature\s*\(", body):
        return True
    if re.search(r"getAndRequireSignature\s*\(", body):
        return True
    if re.search(r"AccountUpdate\s*\.\s*createSigned\s*\(", body):
        return True
    # `someSignature.verify(pubkey, msg).assertTrue()` style
    if re.search(r"\b\w*[Ss]ignature\w*\s*\.\s*verify\s*\(", body):
        return True
    return False


def _split_top_level(s: str, sep: str) -> List[str]:
    """Split ``s`` on ``sep`` characters that sit at paren/bracket/brace depth 0."""
    out: List[str] = []
    depth = 0
    cur: List[str] = []
    for ch in s:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == sep and depth == 0:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    out.append("".join(cur))
    return out


def _send_object_keys(seg: str, arg: str) -> Optional[Set[str]]:
    """For the argument text of a ``this.send(...)`` call, return the set of
    object-literal keys whose value mentions ``arg`` (shorthand ``{ amount }``
    counts as key ``amount``). Returns ``None`` when there is no object literal
    (e.g. a positional ``this.send(pk, amt)`` form)."""
    lb = seg.find("{")
    if lb == -1:
        return None
    depth = 0
    rb = len(seg)
    for i in range(lb, len(seg)):
        if seg[i] == "{":
            depth += 1
        elif seg[i] == "}":
            depth -= 1
            if depth == 0:
                rb = i
                break
    inner = seg[lb + 1:rb]
    a = re.escape(arg)
    keys: Set[str] = set()
    for part in _split_top_level(inner, ","):
        if not part.strip():
            continue
        kv = _split_top_level(part, ":")
        key = kv[0].strip()
        val = ":".join(kv[1:]) if len(kv) > 1 else kv[0]  # shorthand: value == key
        if re.search(r"\b" + a + r"\b", val):
            keys.add(key)
    return keys


def _paren_segment(s: str, open_paren_idx: int) -> str:
    """Return the text inside the parentheses starting at ``open_paren_idx``."""
    depth = 0
    i = open_paren_idx
    n = len(s)
    start = open_paren_idx + 1
    while i < n:
        c = s[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return s[start:i]
        i += 1
    return s[start:]


def _method_param_blob(src: str, meth: "_Method") -> str:
    """Re-extract the raw (typed) parameter list for a method by name, so the
    raw-Field detector can see `name: Field` type annotations (the stripped
    param-name list discards types)."""
    m = re.search(
        r"@method[^\n]*\n?\s*(?:async\s+)?" + re.escape(meth.name)
        + r"\s*\((?P<p>[^)]{0,%d})\)" % _MAX_PARAMS,
        src, re.DOTALL,
    )
    if m:
        return m.group("p")
    m2 = re.search(
        re.escape(meth.name) + r"\s*\((?P<p>[^)]{0,%d})\)" % _MAX_PARAMS, src, re.DOTALL)
    return m2.group("p") if m2 else ""


def analyze_file(filepath: str, source: str) -> List[Vulnerability]:
    """Analyze a single file's ``source`` text."""
    return O1jsLexer().analyze(source, Path(filepath))


def analyze_project(root: str) -> List[Tuple[str, Vulnerability]]:
    """Scan every o1js ``.ts``/``.js`` file under ``root`` (skipping
    ``node_modules``). Returns ``[(filepath, vuln), ...]``."""
    lexer = O1jsLexer()
    out: List[Tuple[str, Vulnerability]] = []
    base = Path(root)
    paths = [base] if base.is_file() else [
        p for pat in ("*.ts", "*.js", "*.mjs")
        for p in base.rglob(pat) if "node_modules" not in str(p)
    ]
    for p in paths:
        try:
            src = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if not is_o1js_source(src, str(p)):
            continue
        for v in lexer.analyze(src, p):
            out.append((str(p), v))
    return out
