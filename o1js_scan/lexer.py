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
   ``> 0``, but never tied to on-chain state).

3. **Permissions & raw-Field amounts.**
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
        vulns += self._detect_raw_field_amount(content, methods)
        vulns += self._detect_weak_permissions(content, stripped)
        return vulns

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
                line = meth.start_line + body.count("\n", 0, effect[1])
                if asserts == "none":
                    out.append(Vulnerability(
                        pattern_name="O1JS_UNCONSTRAINED_WITNESS",
                        severity=Severity.HIGH if effect[0] == "send" else Severity.MEDIUM,
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

    @staticmethod
    def _witness_effect(body: str, arg: str) -> Optional[Tuple[str, int, str]]:
        """Return (effect_kind, offset, expr) if ``arg`` flows into a
        state-changing effect: send amount, state .set(), or .send to."""
        a = re.escape(arg)
        # this.send({ ..., amount: <arg...> }) or this.send({to: <arg...>})
        for sm in re.finditer(r"this\s*\.\s*send\s*\(", body):
            # grab the argument object up to matching )
            seg = _paren_segment(body, sm.end() - 1)
            if re.search(r"\b" + a + r"\b", seg):
                return ("send", sm.start(), seg.strip()[:80])
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
        # X.assertEquals(Y) / X.requireEquals(Y) where X or Y is arg
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
            if kind in ("assertEquals", "requireEquals"):
                # bound if the OTHER side references on-chain-state-derived var
                other = inner if re.search(r"\b" + a + r"\b", recv) else recv
                if any(re.search(r"\b" + re.escape(sb) + r"\b", other) for sb in state_bound) \
                        or "getAndRequireEquals" in other or ".get()" in other:
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
                if eff and eff[0] == "send" and "amount" in eff[2]:
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
