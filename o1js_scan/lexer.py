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
   Binding may live in an undecorated same-class helper called as
   ``this.verifyX(witness)`` — one level of helper-binding propagation covers
   that (see below).

4. **Proof-typed arguments.** A ``@method`` parameter typed as ``Proof<...>``,
   ``SelfProof<...>``, ``DynamicProof<...>``, or a class name ending in
   ``Proof`` is a recursive-proof witness. Once ``proof.verify()`` /
   ``proof.verifyIf(...)`` succeeds, the proof and its ``publicOutput`` /
   ``publicInput`` are constrained by the verified circuit — so witness
   findings on them are suppressed. If the proof is NEVER verified in the
   method body, that IS a bug: Rule: ``O1JS_UNVERIFIED_PROOF``.

5. **Permissions & raw-Field amounts.**
   - ``account.permissions.set`` with ``editState`` / ``send`` set to
     ``proofOrSignature()`` or ``none()`` means the zkApp account key can
     bypass the proof logic by signing — defeating the whole circuit.
     ``setVerificationKey`` / ``setPermissions`` left at ``signature`` /
     ``proofOrSignature`` / ``none`` are Mina's documented training-wheel
     upgrade gates (the account key can redeploy or rewrite permissions).
     Rule: ``O1JS_WEAK_PERMISSIONS``.
   - A raw ``Field`` (NOT ``UInt64``/``UInt32``, which are range-checked by
     construction) used as a transfer amount can exceed the field modulus
     intent / wrap. Rule: ``MissingRangeCheck``.

6. **Logic outside the proof.** ``Provable.asProver(() => { ... })`` (and
   security logic stuffed into a ``Provable.witness`` callback) runs *outside*
   the circuit — asserts / approve / send / state writes there do not bind
   the proof. Rule: ``O1JS_LOGIC_OUTSIDE_PROOF``.

7. **Token approve without binding.** ``this.approve(update)`` /
   ``approveAccountUpdate`` / ``approveBase`` without reading
   ``balanceChange`` / ``publicKey`` (or calling ``assertCanMint`` /
   ``assertCanBurn``) trusts the caller-supplied AccountUpdate. Rule:
   ``O1JS_APPROVE_WITHOUT_BINDING``.

8. **Vacuous / conditional asserts.** Self-comparisons
   (``x.assertEquals(x)``) and asserts gated by a prover-controlled ``if``
   (Noir ``NOIR_VACUOUS_CONSTRAINT`` / ``NOIR_CONDITIONAL_ASSERT`` analogs).
   Rules: ``O1JS_VACUOUS_ASSERT``, ``O1JS_CONDITIONAL_ASSERT``.

Lexical, not full TS AST: o1js code is decorator + brace-delimited-method-body
shaped, regex-tractable, and the output is meant to be hand-triaged. Env
kill-switch: ``AUDIT_O1JS_LEXER=0``.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union

from .paths import ScanStats
from .semantic import SemanticFacts
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
# Bool-returning o1js predicates — return a Bool, do NOT constrain on their own.
_BOOL_PREDICATES = (
    "equals", "notEquals",
    "lessThan", "lessThanOrEqual", "greaterThan", "greaterThanOrEqual",
    "isZero", "isEven", "isConstant",
    "and", "or", "not",
)
_BOOL_PRED_ALT = "|".join(_BOOL_PREDICATES)
_BOOL_PRED_CALL_RE = re.compile(r"\.(" + _BOOL_PRED_ALT + r")\s*\(")
_BOOL_PRED_ASSIGN_RE = re.compile(
    r"\b(?:const|let|var)\s+(\w{1,%d})\s*=\s*"
    r"(?:[^;]{0,%d}?)\.(" % (_MAX_IDENT, _MAX_CALL_ARG)
    + _BOOL_PRED_ALT
    + r")\s*\("
)
_SENDER_UNCONSTRAINED_RE = re.compile(
    r"this\s*\.\s*sender\s*\.\s*getUnconstrained\s*\(\s*\)"
)
_SENDER_REQUIRE_SIG_RE = re.compile(
    r"this\s*\.\s*sender\s*\.\s*getAndRequireSignature\s*\("
)
_SENDER_UNCONSTRAINED_ASSIGN_RE = re.compile(
    r"\b(?:const|let|var)\s+(\w{1,%d})\s*=\s*"
    r"(?:[^;]{0,%d}?this\s*\.\s*sender\s*\.\s*getUnconstrained\s*\()" % (
        _MAX_IDENT, _MAX_CALL_ARG,
    ),
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
# Provable.asProver / Provable.witness* — callback bodies run outside the circuit.
_ASPROVER_CALL_RE = re.compile(r"Provable\s*\.\s*asProver\s*\(")
_PROVABLE_HINT_CALL_RE = re.compile(
    r"Provable\s*\.\s*(asProver|witness|witnessFields|witnessAsync)\s*\("
)
# Security-relevant ops that are useless (or actively misleading) outside a proof.
_OUTSIDE_PROOF_EFFECT_RE = re.compile(
    r"(?:"
    r"\.(?:assertEquals|assertTrue|assertFalse|assertLessThan|assertLessThanOrEqual|"
    r"assertGreaterThan|assertGreaterThanOrEqual|assertNotEquals|assertBool|"
    r"requireEquals)\s*\("
    r"|this\s*\.\s*(?:approve|approveAccountUpdate|approveAccountUpdates|approveBase|"
    r"send|assertCanMint|assertCanBurn)\s*\("
    r"|(?:approveAccountUpdate|approveAccountUpdates|approveBase)\s*\("
    r"|\.set\s*\("
    r")"
)
_APPROVE_CALL_RE = re.compile(
    r"(?:this\s*\.\s*)?(?:approve|approveAccountUpdate|approveAccountUpdates|"
    r"approveBase)\s*\("
)
_APPROVE_BINDING_RE = re.compile(
    r"(?:balanceChange|\.publicKey\b|assertCanMint|assertCanBurn|"
    r"forEachUpdate|totalBalanceChange)"
)
_VACUOUS_ASSERT_EQ_RE = re.compile(
    # Bare receiver only — `x.assertEquals(x)`. Dotted paths like
    # `update.body.tokenId.assertEquals(tokenId)` share a basename but compare
    # distinct values and must NOT match.
    r"(?<![.\w])(\w{1,%d})\s*\.\s*assertEquals\s*\(\s*\1\s*\)" % _MAX_IDENT,
)
_VACUOUS_EQUALS_ASSERT_RE = re.compile(
    r"(?<![.\w])(\w{1,%d})\s*\.\s*equals\s*\(\s*\1\s*\)\s*\.\s*assertTrue\s*\("
    % _MAX_IDENT,
)
_VACUOUS_CONST_BOOL_RE = re.compile(
    r"\bBool\s*\(\s*(true|false)\s*\)\s*\.\s*assert(?:True|False)\s*\("
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
    __slots__ = (
        "name", "params", "param_types", "body", "start_line",
        "is_method_decorated", "semantic_scope",
    )

    def __init__(
        self, name, params, body, start_line, is_method_decorated,
        param_types=None, semantic_scope=0,
    ):
        self.name = name
        self.params = params                # List[str] param names
        self.param_types = param_types or [None] * len(params)  # parallel type strings
        self.body = body
        self.start_line = start_line
        self.is_method_decorated = is_method_decorated
        self.semantic_scope = semantic_scope


_FUNC_HEAD_RE = re.compile(
    r"(?P<deco>@method(?:\.returns\([^)]{0,%d}\))?\s+)?"
    r"(?:async\s+)?(?P<name>\w{1,%d})\s*\((?P<params>[^)]{0,%d})\)\s*"
    r"(?::\s*[^{]{1,%d})?\{" % (_MAX_PARAMS, _MAX_IDENT, _MAX_PARAMS, _MAX_PARAMS),
)
# Same-class helper call: `this.<helper>(...)`. Depth-1 binding propagation only.
_THIS_HELPER_CALL_RE = re.compile(
    r"this\s*\.\s*(\w{1,%d})\s*\(" % _MAX_IDENT,
)


def _extract_methods(stripped: str, full_src: str) -> List[_Method]:
    """Brace-balanced extraction of every method-like body in the contract,
    flagging which carry the ``@method`` decorator."""
    methods: List[_Method] = []
    # Give semantic consumers a stable declaring-contract identity.  Names are
    # insufficient because a source file may declare several SmartContracts.
    contract_starts = [m.start() for m in _SMARTCONTRACT_RE.finditer(stripped)]
    for m in _FUNC_HEAD_RE.finditer(stripped):
        name = m.group("name")
        if name in ("if", "for", "while", "switch", "catch", "function"):
            continue
        params_raw = m.group("params")
        parsed = _parse_params(params_raw)
        param_names = [p[0] for p in parsed]
        param_types = [p[1] for p in parsed]
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
            param_types=param_types,
            body=body,
            start_line=_line_of(full_src, m.start()),
            is_method_decorated=bool(m.group("deco")),
            semantic_scope=sum(start <= m.start() for start in contract_starts),
        ))
    return methods


def _parse_params(params_raw: str) -> List[Tuple[str, Optional[str]]]:
    """`a: Field, b: PublicKey` -> [('a','Field'), ('b','PublicKey')]
    (depth-aware on <> and ())."""
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
    parsed: List[Tuple[str, Optional[str]]] = []
    for raw in out:
        raw = raw.strip()
        if not raw:
            continue
        # strip default values
        raw = raw.split("=")[0]
        typ: Optional[str] = None
        if ":" in raw:
            name_part, type_part = raw.split(":", 1)
            name = name_part.strip().lstrip(".")
            typ = type_part.strip() or None
        else:
            name = raw.strip().lstrip(".")
        name = re.sub(r"^\{.*\}$", "", name)  # skip destructured params
        if re.fullmatch(r"\w+", name):
            parsed.append((name, typ))
    return parsed


def _parse_param_names(params_raw: str) -> List[str]:
    """Back-compat: names only."""
    return [n for n, _t in _parse_params(params_raw)]


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
        semantic_facts = SemanticFacts(methods, state)
        # Depth-1: undecorated same-class helpers → which param indices they bind.
        helper_binds = self._build_helper_binds(methods, state)

        vulns: List[Vulnerability] = []
        vulns += self._detect_missing_state_precondition(content, stripped, methods, state)
        vulns += self._detect_unconstrained_witness(
            content, methods, state, helper_binds, semantic_facts
        )
        vulns += self._detect_unconstrained_provable_witness(content, methods, state)
        vulns += self._detect_stale_merkle_root(content, methods, state, helper_binds)
        vulns += self._detect_unverified_proof(content, methods, state)
        vulns += self._detect_unasserted_bool(content, methods)
        vulns += self._detect_unconstrained_sender(content, methods)
        vulns += self._detect_raw_field_amount(content, methods)
        vulns += self._detect_logic_outside_proof(content, methods)
        vulns += self._detect_approve_without_binding(content, methods)
        vulns += self._detect_vacuous_assert(content, methods)
        vulns += self._detect_conditional_assert(content, methods)
        vulns += self._detect_weak_permissions(content, stripped)
        return _apply_suppressions(content, vulns)

    # --- Cross-method binding (depth-1 helper propagation) ----------------

    def _build_helper_binds(
        self, methods: List[_Method], state: Dict[str, str],
    ) -> Dict[str, Set[int]]:
        """Map undecorated helper name → parameter indices it state-binds.

        Only helpers with a non-empty binds set are entered (an empty set would
        propagate nothing anyway; omitting them also means calling a no-op
        helper cannot launder a witness). ``@method``-decorated methods are
        never treated as helpers."""
        out: Dict[str, Set[int]] = {}
        for meth in methods:
            if meth.is_method_decorated:
                continue
            state_bound = _state_bound_locals(meth.body, state)
            idxs: Set[int] = set()
            for i, pname in enumerate(meth.params):
                if self._asserts_on(meth.body, pname, state_bound) == "bound":
                    idxs.add(i)
            if idxs:
                out[meth.name] = idxs
        return out

    @staticmethod
    def _propagated_bindings(body: str, helper_binds: Dict[str, Set[int]]) -> Set[str]:
        """Identifiers in ``body`` that a same-class helper call state-binds.

        Only ``this.<helper>(...)`` calls; positional index mapping; root
        identifier of each matching arg (leading ident before ``.`` / ``[``).
        Depth 1 only — helpers are never followed further."""
        if not helper_binds:
            return set()
        bound: Set[str] = set()
        for m in _THIS_HELPER_CALL_RE.finditer(body):
            name = m.group(1)
            idxs = helper_binds.get(name)
            if not idxs:
                continue
            args_seg = _paren_segment(body, m.end() - 1)
            args = _split_top_level(args_seg, ",")
            for i in idxs:
                if i >= len(args):
                    continue
                root = _arg_root_ident(args[i])
                if root:
                    bound.add(root)
        return bound

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
                    + r"\s*\.\s*(getAndRequireEquals|getAndAssertEquals|requireEquals|assertEquals)\s*\(",
                    body,
                )
                # also accept getAndRequireEquals used INSTEAD of get (no bare get)
                only_safe_form = re.search(
                    r"this\s*\.\s*" + re.escape(field_name)
                    + r"\s*\.\s*(?:getAndRequireEquals|getAndAssertEquals)",
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
        helper_binds: Optional[Dict[str, Set[int]]] = None,
        semantic_facts: Optional[SemanticFacts] = None,
    ) -> List[Vulnerability]:
        helper_binds = helper_binds or {}
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
            # PLUS identifiers state-bound via a depth-1 same-class helper call.
            state_bound: Set[str] = _state_bound_locals(body, state)
            state_bound |= _simple_aliases(body, state_bound)
            helper_bound = self._propagated_bindings(body, helper_binds)
            state_bound |= helper_bound

            for arg_i, arg in enumerate(meth.params):
                typ = meth.param_types[arg_i] if arg_i < len(meth.param_types) else None
                # Proof-typed args are owned by O1JS_UNVERIFIED_PROOF / the
                # verify() suppression — not the generic witness rules.
                if _is_proof_type(typ):
                    continue
                aliases = _simple_aliases(body, {arg})
                semantic_effect, semantic_asserts = (
                    semantic_facts.witness(meth, arg_i)
                    if semantic_facts else (None, "none")
                )
                effect = self._witness_effect(body, aliases)
                if effect is None and semantic_effect is not None:
                    effect = (
                        semantic_effect.kind, semantic_effect.offset,
                        semantic_effect.expression,
                    )
                if effect is None:
                    continue  # arg not used in any state-changing effect → ignore
                asserts = self._asserts_on(body, aliases, state_bound)
                if semantic_asserts == "bound" or (
                    semantic_asserts == "trivial" and asserts == "none"
                ):
                    asserts = semantic_asserts
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
                            f"`{arg}` is the `to:` recipient of a `send(...)` in "
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
            state_bound: Set[str] = _state_bound_locals(body, state)
            state_bound |= _simple_aliases(body, state_bound)

            for wm in _PROVABLE_WITNESS_RE.finditer(body):
                name, api = wm.group(1), wm.group(2)
                aliases = _simple_aliases(body, {name})
                effect = self._witness_effect(body, aliases)
                if effect is None:
                    continue  # witness never reaches a state-changing effect
                if self._asserts_on(body, aliases, state_bound) != "none":
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
        helper_binds: Optional[Dict[str, Set[int]]] = None,
    ) -> List[Vulnerability]:
        """Flag a method that recomputes a Merkle root from a prover-supplied
        witness but binds NONE of the recomputed roots to the current on-chain
        root. Per-method (not per-root) on purpose: a correct tree update legitimately
        leaves the NEW root unasserted (it is what gets ``set``), so the soundness
        requirement is that at least one witness-derived root is tied to the
        current on-chain state — proving the witness matches the live tree.

        Binding may live in an undecorated same-class helper
        (``this.verifyX(witness)``); a witness receiver that appears in the
        depth-1 helper-propagated bound set counts as verified."""
        if not state:
            return []
        helper_binds = helper_binds or {}
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
            state_bound: Set[str] = _state_bound_locals(body, state)
            helper_bound = self._propagated_bindings(body, helper_binds)
            state_bound |= helper_bound

            # Witness receiver itself state-bound via helper → tree membership
            # was checked in the helper; do not flag.
            if any(recv in helper_bound for _rv, recv, _api, _off in roots):
                continue
            if any(self._merkle_root_bound(body, rv, state, state_bound)
                   for rv, _, _, _ in roots):
                continue  # at least one recomputed root is tied to the live tree
            if any(self._inline_merkle_witness_bound(body, recv, state, state_bound)
                   for _, recv, _, _ in roots):
                continue  # binding uses inline `recv.calculateRoot(...)` in an assert
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

    # --- Rule 2d: proof-typed arg never verified --------------------------

    def _detect_unverified_proof(
        self, src: str, methods: List[_Method], state: Dict[str, str],
    ) -> List[Vulnerability]:
        """A Proof/SelfProof/DynamicProof / ``*Proof`` typed ``@method``
        argument that is never unconditionally ``.verify()``'d before its public
        fields are used. A ``verifyIf`` gated by an unconstrained method
        argument is not enough: the prover can choose the condition that skips
        recursive proof verification."""
        out: List[Vulnerability] = []
        for meth in methods:
            if not meth.is_method_decorated:
                continue
            body = meth.body
            if _method_is_signature_gated(body):
                continue
            state_bound: Set[str] = _state_bound_locals(body, state)
            state_bound |= _simple_aliases(body, state_bound)
            for i, arg in enumerate(meth.params):
                typ = meth.param_types[i] if i < len(meth.param_types) else None
                if not _is_proof_type(typ):
                    continue
                if _proof_has_unconditional_verify(body, arg):
                    continue
                unsafe_verify_if = _unsafe_proof_verify_if(body, arg, meth.params, state_bound)
                if unsafe_verify_if and _proof_public_fields_used(body, arg):
                    cond, verify_off = unsafe_verify_if
                    line = meth.start_line + body.count("\n", 0, verify_off)
                    out.append(Vulnerability(
                        pattern_name="O1JS_UNVERIFIED_PROOF",
                        severity=Severity.HIGH,
                        function=meth.name,
                        location=(line, 0),
                        origin_tier=O1JS_ORIGIN_TIER,
                        rule_id="O1JS_UNVERIFIED_PROOF",
                        title=(
                            f"Proof `{arg}` is verified only under prover-controlled "
                            f"condition `{cond}` in `{meth.name}`"
                        ),
                        description=(
                            f"`{arg}.verifyIf({cond})` is controlled by a private "
                            f"`@method` argument, while `{meth.name}` reads "
                            f"`{arg}.publicOutput` / `publicInput`. A malicious prover can "
                            f"choose the condition so the recursive proof is not verified, "
                            f"then supply arbitrary public fields. Assert the condition true "
                            f"before `verifyIf`, or call `{arg}.verify()` unconditionally."
                        ),
                        evidence={
                            "witness": arg,
                            "proof_type": typ,
                            "verify_condition": cond,
                            "method": meth.name,
                            "framework": "o1js",
                        },
                    ))
                    continue
                if _proof_has_verify_if(body, arg):
                    continue
                # OffchainState.settle(proof) verifies the recursive settlement
                # proof inside the framework API (Mina docs canonical pattern).
                # Only this exact receiver/method pair — a custom `.settle(proof)`
                # is NOT assumed to verify and must still fire.
                if _proof_settled_via_offchain_state(body, arg):
                    continue
                # Locate the parameter declaration line approximately via method start.
                line = meth.start_line
                out.append(Vulnerability(
                    pattern_name="O1JS_UNVERIFIED_PROOF",
                    severity=Severity.HIGH,
                    function=meth.name,
                    location=(line, 0),
                    origin_tier=O1JS_ORIGIN_TIER,
                    rule_id="O1JS_UNVERIFIED_PROOF",
                    title=f"Proof `{arg}` is never verified in `{meth.name}`",
                    description=(
                        f"`{arg}` is typed as a proof (`{typ}`) but `{meth.name}` never "
                        f"calls `{arg}.verify()` / `{arg}.verifyIf(...)`. Passing a Proof "
                        f"to a `@method` does not verify it — without an explicit verify "
                        f"the prover can supply an arbitrary proof object, and any use of "
                        f"its `publicOutput` / `publicInput` is unconstrained. Call "
                        f"`{arg}.verify()` before reading its public fields."
                    ),
                    evidence={
                        "witness": arg,
                        "proof_type": typ,
                        "method": meth.name,
                        "framework": "o1js",
                    },
                ))
        return out

    # --- Rule 2e: discarded Bool predicate (unasserted comparison) --------

    def _detect_unasserted_bool(
        self, src: str, methods: List[_Method],
    ) -> List[Vulnerability]:
        """o1js predicates (``equals`` / ``lessThanOrEqual`` / …) return a Bool
        and add NO constraint unless the result is asserted or otherwise used.
        Tier A (HIGH): bare expression-statement whose outermost call is a
        predicate with nothing chained after it.
        Tier B (MEDIUM): ``const|let|var x = <expr>.<pred>(...)`` where ``x``
        is never referenced again in the method body."""
        out: List[Vulnerability] = []
        for meth in methods:
            if not meth.is_method_decorated:
                continue
            body = meth.body
            statements = _split_statements(body)

            # --- Tier A: bare discarded predicate statement ---------------
            for stmt, stmt_off in statements:
                trimmed = stmt.strip()
                if not trimmed:
                    continue
                if re.match(r"^(?:return|const|let|var)\b", trimmed):
                    continue
                if _has_top_level_assign(trimmed):
                    continue
                # A predicate call whose closing paren is the end of the statement
                # (nothing chained after — .assertTrue() / .and() / etc. suppress).
                for pm in _BOOL_PRED_CALL_RE.finditer(trimmed):
                    open_paren = pm.end() - 1
                    close = _matching_paren_end(trimmed, open_paren)
                    if close is None:
                        continue
                    if trimmed[close + 1:].strip():
                        continue  # something follows — value is consumed
                    pred = pm.group(1)
                    # Receiver text for the title (trim to a short display form).
                    recv = trimmed[:pm.start()].strip()
                    recv_disp = recv[-40:] if len(recv) > 40 else recv
                    line = meth.start_line + body.count("\n", 0, stmt_off + pm.start())
                    out.append(Vulnerability(
                        pattern_name="O1JS_UNASSERTED_BOOL",
                        severity=Severity.HIGH,
                        function=meth.name,
                        location=(line, 0),
                        origin_tier=O1JS_ORIGIN_TIER,
                        rule_id="O1JS_UNASSERTED_BOOL",
                        title=(
                            f"Comparison `{recv_disp}.{pred}(...)` result is discarded "
                            f"in `{meth.name}`"
                        ),
                        description=(
                            f"In o1js, `{pred}()` returns a `Bool` and adds NO circuit "
                            f"constraint on its own. The statement `{trimmed[:80]}` "
                            f"discards that Bool, so the comparison is a no-op in the "
                            f"proof. Chain `.assertTrue()` / `.assertFalse()`, or use "
                            f"the Bool in `Provable.if(...)` / a further `.and()`/`.or()` "
                            f"that is itself asserted."
                        ),
                        evidence={
                            "predicate": pred,
                            "method": meth.name,
                            "tier": "bare_statement",
                            "framework": "o1js",
                        },
                    ))
                    break  # one finding per statement

            # --- Tier B: assigned predicate never used --------------------
            for stmt, stmt_off in statements:
                am = _BOOL_PRED_ASSIGN_RE.search(stmt)
                if not am:
                    continue
                # The predicate call must close such that the assignment RHS is
                # essentially the predicate result (allow trailing whitespace /
                # semicolon already stripped by statement split).
                open_paren = am.end() - 1
                # open_paren is relative to stmt; am.start is in stmt
                close = _matching_paren_end(stmt, open_paren)
                if close is None:
                    continue
                after = stmt[close + 1:].strip()
                if after:
                    # e.g. `const ok = x.equals(y).assertTrue()` — consumed
                    continue
                name = am.group(1)
                pred = am.group(2)
                # Rest of the method body after this statement.
                rest = body[stmt_off + len(stmt):]
                if re.search(r"\b" + re.escape(name) + r"\b", rest):
                    continue  # used anywhere later → not a finding
                line = meth.start_line + body.count("\n", 0, stmt_off + am.start())
                out.append(Vulnerability(
                    pattern_name="O1JS_UNASSERTED_BOOL",
                    severity=Severity.MEDIUM,
                    function=meth.name,
                    location=(line, 0),
                    origin_tier=O1JS_ORIGIN_TIER,
                    rule_id="O1JS_UNASSERTED_BOOL",
                    title=(
                        f"Comparison result `{name}` is computed but never used "
                        f"in `{meth.name}`"
                    ),
                    description=(
                        f"`{name}` is assigned the result of `{pred}()` (an o1js "
                        f"`Bool`) but is never referenced again in `{meth.name}`. "
                        f"The comparison adds no constraint. Assert it "
                        f"(`{name}.assertTrue()`), branch on it (`Provable.if`), "
                        f"or remove the dead check."
                    ),
                    evidence={
                        "predicate": pred,
                        "local": name,
                        "method": meth.name,
                        "tier": "unused_local",
                        "framework": "o1js",
                    },
                ))

        return out

    # --- Rule 2f: this.sender.getUnconstrained() --------------------------

    def _detect_unconstrained_sender(
        self, src: str, methods: List[_Method],
    ) -> List[Vulnerability]:
        """``this.sender.getUnconstrained()`` returns the tx sender WITHOUT
        proving it. Using that value in an assert/set/send makes the check
        vacuous (both sides prover-chosen) — unless the same method
        authenticates the sender via ``getAndRequireSignature()`` or
        ``AccountUpdate.createSigned(<that sender>)`` (the idiomatic
        expanded form of getAndRequireSignature)."""
        out: List[Vulnerability] = []
        for meth in methods:
            if not meth.is_method_decorated:
                continue
            body = meth.body
            if not _SENDER_UNCONSTRAINED_RE.search(body):
                continue

            # FP2: getAndRequireSignature anywhere in THIS method authenticates
            # the sender for the whole method (method-scoped, not call-site).
            if _SENDER_REQUIRE_SIG_RE.search(body):
                continue

            # Locals assigned from getUnconstrained (incl. chained .toFields()).
            tainted: Set[str] = set()
            for am in _SENDER_UNCONSTRAINED_ASSIGN_RE.finditer(body):
                tainted.add(am.group(1))

            # FP1: AccountUpdate.createSigned(<same sender>) / create+requireSignature
            # authenticates that witnessed key — treat as constrained.
            if _sender_authenticated_via_account_update(body, tainted):
                continue

            load_bearing = _sender_unconstrained_is_load_bearing(body, tainted)
            # First occurrence for line attribution.
            first = _SENDER_UNCONSTRAINED_RE.search(body)
            line = meth.start_line + body.count("\n", 0, first.start())
            sev = Severity.HIGH if load_bearing else Severity.MEDIUM
            out.append(Vulnerability(
                pattern_name="O1JS_UNCONSTRAINED_SENDER",
                severity=sev,
                function=meth.name,
                location=(line, 0),
                origin_tier=O1JS_ORIGIN_TIER,
                rule_id="O1JS_UNCONSTRAINED_SENDER",
                title=(
                    f"Sender obtained via getUnconstrained() is prover-chosen "
                    f"in `{meth.name}`"
                ),
                description=(
                    "`this.sender.getUnconstrained()` returns the transaction "
                    "sender WITHOUT adding a proof constraint (o1js documents "
                    "this explicitly). Using that value in an assert, state "
                    "write, or send makes the check vacuous — the prover "
                    "chooses both sides. Use "
                    "`this.sender.getAndRequireSignature()` for a constrained "
                    "sender, or authenticate it with "
                    "`AccountUpdate.createSigned(sender)`."
                ),
                evidence={
                    "method": meth.name,
                    "load_bearing": load_bearing,
                    "tainted_locals": sorted(tainted),
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
            if "getAndRequireEquals" in expr or "getAndAssertEquals" in expr or ".get()" in expr:
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
            if re.search(r"\b" + rv + r"\b", recv) and _state_derived(inner):
                return True
            if re.search(r"\b" + rv + r"\b", inner) and _state_derived(recv):
                return True
        return False

    @staticmethod
    def _inline_merkle_witness_bound(
        body: str, witness_recv: str, state: Dict[str, str], state_bound: Set[str],
    ) -> bool:
        """True when membership is checked via inline ``recv.calculateRoot(...)``.

        Covers ``rootBefore.assertEquals(leafWitness.calculateRoot(...))`` where
        the recomputed root is never assigned to a named local (privacy-coin shape).
        """
        recv = re.escape(witness_recv)
        calc = (
            r"(?:calculateRoot|computeRootAndKey|computeRootAndKeyV2)\s*\("
        )
        # state_local.assertEquals(recv.calculateRoot(...))
        for sb in state_bound:
            if re.search(
                r"\b" + re.escape(sb)
                + r"\s*\.\s*(?:assertEquals|requireEquals)\s*\(\s*"
                + recv + r"\s*\.\s*" + calc,
                body,
            ):
                return True
        # this.<root>.assertEquals(recv.calculateRoot(...))
        for field in state:
            if re.search(
                r"this\s*\.\s*" + re.escape(field)
                + r"\s*\.\s*(?:assertEquals|requireEquals)\s*\(\s*"
                + recv + r"\s*\.\s*" + calc,
                body,
            ):
                return True
        # recv.calculateRoot(...).assertEquals(state_local) — uncommon but sound
        if re.search(
            recv + r"\s*\.\s*" + calc + r"[^;]{0,%d}?\)\s*\.\s*"
            r"(?:assertEquals|requireEquals)\s*\(" % _MAX_CALL_ARG,
            body,
        ):
            # verify the other side is state-derived
            for m in re.finditer(
                recv + r"\s*\.\s*(?:calculateRoot|computeRootAndKey|computeRootAndKeyV2)"
                r"\s*\([^;]{0,%d}?\)\s*\.\s*(?:assertEquals|requireEquals)\s*\(([^;]{0,%d}?)\)"
                % (_MAX_CALL_ARG, _MAX_CALL_ARG),
                body,
            ):
                other = m.group(1)
                if any(re.search(r"\b" + re.escape(sb) + r"\b", other) for sb in state_bound):
                    return True
                if re.search(r"this\s*\.\s*\w+", other):
                    return True
        return False

    @staticmethod
    def _witness_effect(body: str, arg: Union[str, Set[str]]) -> Optional[Tuple[str, int, str]]:
        """Return (effect_kind, offset, expr) if ``arg``/an alias flows into a
        state-changing effect. Effect kinds:
          * ``send_amount``    — arg appears in the ``amount:`` value of a send
          * ``send_recipient`` — arg appears ONLY in the ``to:`` value of a send
          * ``state_set``      — arg flows into a ``this.<state>.set(...)``
        A witness that appears in both ``amount`` and ``to`` is ``send_amount``
        (the higher-severity effect wins)."""
        aliases = {arg} if isinstance(arg, str) else set(arg)

        def _classify_send(seg: str) -> Optional[str]:
            keys: Optional[Set[str]] = set()
            positional = False
            for hit in aliases:
                hit_keys = _send_object_keys(seg, hit)
                if hit_keys is None:
                    if not re.search(r"\b" + re.escape(hit) + r"\b", seg):
                        continue
                    positional = True
                    keys = None
                    break
                keys |= hit_keys
            if keys is not None and not keys and not positional:
                return None
            if keys is not None and "amount" not in keys and "to" in keys:
                return "send_recipient"
            # amount value, both, a positional send, or some other key:
            # treat as the amount-flow (higher severity) conservatively.
            return "send_amount"

        # this.send({ ..., amount: <arg...> }) or this.send({to: <arg...>})
        for sm in re.finditer(r"this\s*\.\s*send\s*\(", body):
            seg = _paren_segment(body, sm.end() - 1)
            kind = _classify_send(seg)
            if kind:
                return (kind, sm.start(), seg.strip()[:80])
        # AccountUpdate.create(...).send(...) / createSigned(...).send(...)
        for sm in re.finditer(
            r"AccountUpdate\s*\.\s*create(?:Signed)?\s*\([^;]{0,%d}?\)\s*\.\s*send\s*\("
            % _MAX_CALL_ARG,
            body,
        ):
            seg = _paren_segment(body, sm.end() - 1)
            kind = _classify_send(seg)
            if kind:
                return (kind, sm.start(), seg.strip()[:80])
        # const au = AccountUpdate.create(...); au.send(...)
        au_locals = _account_update_locals(body)
        for sm in re.finditer(r"\b(\w+)\s*\.\s*send\s*\(", body):
            if sm.group(1) not in au_locals:
                continue
            seg = _paren_segment(body, sm.end() - 1)
            kind = _classify_send(seg)
            if kind:
                return (kind, sm.start(), seg.strip()[:80])
        # this.<state>.set(<arg ...>)
        for sm in re.finditer(r"this\s*\.\s*\w+\s*\.\s*set\s*\(", body):
            seg = _paren_segment(body, sm.end() - 1)
            if any(re.search(r"\b" + re.escape(a) + r"\b", seg) for a in aliases):
                return ("state_set", sm.start(), seg.strip()[:80])
        return None

    @staticmethod
    def _asserts_on(body: str, arg: Union[str, Set[str]], state_bound: Set[str]) -> str:
        """Classify how ``arg``/an alias is constrained: 'bound' (tied to on-chain
        state / signature), 'trivial' (only >0 / !=0 / boolean), or 'none'."""
        aliases = {arg} if isinstance(arg, str) else set(arg)
        # collect every assert*/requireEquals expression that mentions arg
        bound = False
        trivial = False
        any_assert = False

        def _mentions_alias(text: str) -> bool:
            return any(re.search(r"\b" + re.escape(a) + r"\b", text) for a in aliases)

        def _state_derived(other: str) -> bool:
            """True if ``other`` references an on-chain-state-derived value."""
            return (any(re.search(r"\b" + re.escape(sb) + r"\b", other) for sb in state_bound)
                    or "getAndRequireEquals" in other or "getAndAssertEquals" in other
                    or ".get()" in other)

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
            in_recv = _mentions_alias(recv)
            in_inner = _mentions_alias(inner)
            mentions = in_recv or in_inner
            if not mentions:
                continue
            any_assert = True
            if kind in _state_bindable:
                # bound if the OTHER side references on-chain-state-derived var
                other = inner if in_recv else recv
                if _state_derived(other):
                    bound = True
                else:
                    trivial = True
            else:
                trivial = True
        # also: equality the other direction `configuredX.assertEquals(arg)`
        for am in re.finditer(
            r"(\w{1,%d})\s*\.\s*(assertEquals|requireEquals)\s*\(\s*(\w+)\s*\)"
            % _MAX_IDENT, body,
        ):
            if am.group(1) in state_bound and am.group(3) in aliases:
                bound = True
                any_assert = True
        # chained-comparison idiom: `amount.lessThanOrEqual(bal).assertTrue()`
        alias_alt = "|".join(re.escape(a) for a in sorted(aliases))
        for cm in re.finditer(
            r"\b(?:" + alias_alt + r")\s*\.\s*(?:lessThan|lessThanOrEqual|greaterThan"
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

    # --- Rule: security logic inside Provable.asProver / witness callbacks -

    def _detect_logic_outside_proof(
        self, src: str, methods: List[_Method],
    ) -> List[Vulnerability]:
        """Flag asserts / approve / send / state writes inside out-of-circuit
        callbacks (Mina secure-zkApps advice #1)."""
        out: List[Vulnerability] = []
        for meth in methods:
            body = meth.body
            for m in _PROVABLE_HINT_CALL_RE.finditer(body):
                api = m.group(1)
                # asProver always runs outside the proof; witness* callbacks are
                # prover hints — both are only flagged when the callback body
                # contains security-relevant ops (empty / Provable.log-only stay quiet).
                if api != "asProver" and api not in ("witness", "witnessFields", "witnessAsync"):
                    continue
                open_paren = m.end() - 1
                args = _paren_segment(body, open_paren)
                cb = _first_callback_brace_body(args)
                if cb is None:
                    continue
                cb_body, _ = cb
                if not _OUTSIDE_PROOF_EFFECT_RE.search(cb_body):
                    continue
                # Locate the offending effect for line attribution.
                em = _OUTSIDE_PROOF_EFFECT_RE.search(cb_body)
                # Offset: start of Provable.* call within method body, then
                # into the callback. Approximate via the call match + effect.
                rel = m.start() + (em.start() if em else 0)
                line = meth.start_line + body.count("\n", 0, rel)
                kind = "asProver" if api == "asProver" else "witness-callback"
                out.append(Vulnerability(
                    pattern_name="O1JS_LOGIC_OUTSIDE_PROOF",
                    severity=Severity.HIGH,
                    function=meth.name,
                    location=(line, 0),
                    origin_tier=O1JS_ORIGIN_TIER,
                    rule_id="O1JS_LOGIC_OUTSIDE_PROOF",
                    title=(
                        f"Security logic inside `Provable.{api}` in `{meth.name}`"
                    ),
                    description=(
                        f"`Provable.{api}(...)` runs *outside* the zk proof — whatever "
                        f"happens in its callback is a prover hint, not a constraint. "
                        f"This `{kind}` contains an assert / approve / send / state write, "
                        f"so a malicious prover can delete or alter that logic and still "
                        f"produce a verifying proof. Move the check into the circuit "
                        f"(unconditional assert / `Provable.if`), or drop the "
                        f"`asProver` wrapper."
                    ),
                    evidence={
                        "method": meth.name,
                        "api": api,
                        "framework": "o1js",
                    },
                ))
        return out

    # --- Rule: approve(AccountUpdate) without binding update fields -------

    def _detect_approve_without_binding(
        self, src: str, methods: List[_Method],
    ) -> List[Vulnerability]:
        """Flag approve* that never reads balanceChange / publicKey / mint-burn guards.

        Distills the Mina docs FlawedTokenContract archetype: approving a
        caller-supplied AccountUpdate without asserting its contents.
        """
        out: List[Vulnerability] = []
        for meth in methods:
            if not meth.is_method_decorated:
                continue
            body = meth.body
            am = _APPROVE_CALL_RE.search(body)
            if not am:
                continue
            if _APPROVE_BINDING_RE.search(body):
                continue
            line = meth.start_line + body.count("\n", 0, am.start())
            out.append(Vulnerability(
                pattern_name="O1JS_APPROVE_WITHOUT_BINDING",
                severity=Severity.MEDIUM,
                function=meth.name,
                location=(line, 0),
                origin_tier=O1JS_ORIGIN_TIER,
                rule_id="O1JS_APPROVE_WITHOUT_BINDING",
                title=f"Token approve without binding update fields in `{meth.name}`",
                description=(
                    f"`{meth.name}` calls `approve` / `approveAccountUpdate` / "
                    f"`approveBase` but never reads `balanceChange` / `publicKey` "
                    f"and never calls `assertCanMint` / `assertCanBurn` (or a "
                    f"`forEachUpdate` total-balance check). Approving a "
                    f"caller-supplied `AccountUpdate` without constraining its "
                    f"contents lets the prover mint/burn/transfer under a "
                    f"mismatched authorization check. Bind the update fields "
                    f"before approving, or extend `TokenContract` and implement "
                    f"`approveBase` with a conservation check."
                ),
                evidence={"method": meth.name, "framework": "o1js"},
            ))
        return out

    # --- Rule: vacuous self-assert / constant Bool assert -----------------

    def _detect_vacuous_assert(
        self, src: str, methods: List[_Method],
    ) -> List[Vulnerability]:
        """Noir ``NOIR_VACUOUS_CONSTRAINT`` analog for o1js."""
        out: List[Vulnerability] = []
        for meth in methods:
            body = meth.body
            seen_lines: Set[int] = set()
            for rx, is_typo, label in (
                (_VACUOUS_ASSERT_EQ_RE, True, "assertEquals(self)"),
                (_VACUOUS_EQUALS_ASSERT_RE, True, "equals(self).assertTrue"),
                (_VACUOUS_CONST_BOOL_RE, False, "constant Bool assert"),
            ):
                for m in rx.finditer(body):
                    line = meth.start_line + body.count("\n", 0, m.start())
                    if line in seen_lines:
                        continue
                    seen_lines.add(line)
                    out.append(Vulnerability(
                        pattern_name="O1JS_VACUOUS_ASSERT",
                        severity=Severity.HIGH if is_typo else Severity.MEDIUM,
                        function=meth.name,
                        location=(line, 0),
                        origin_tier=O1JS_ORIGIN_TIER,
                        rule_id="O1JS_VACUOUS_ASSERT",
                        title=f"Vacuous assert ({label}) in `{meth.name}`",
                        description=(
                            f"This assert is satisfied by construction ({label}), so it "
                            f"adds no restriction to the circuit. A vacuous assert is more "
                            f"dangerous than a missing one: the code reads as checked while "
                            f"the prover remains free. "
                            + (
                                "A self-comparison is almost always a typo for a real check "
                                "(`computed.assertEquals(expected)` mistyped as "
                                "`expected.assertEquals(expected)`)."
                                if is_typo else
                                "Replace the constant Bool assert with a real constraint, "
                                "or remove it."
                            )
                        ),
                        evidence={
                            "method": meth.name,
                            "kind": label,
                            "framework": "o1js",
                        },
                    ))
        return out

    # --- Rule: assert gated by prover-controlled JS if --------------------

    def _detect_conditional_assert(
        self, src: str, methods: List[_Method],
    ) -> List[Vulnerability]:
        """Noir ``NOIR_CONDITIONAL_ASSERT`` analog — JS ``if`` over a Bool witness.

        Inline comparisons (``if (x.equals(y))``) stay unreported; bare
        identifier gates (and ``.toBoolean()``) derived from ``@method`` Bool
        args are reported when the block contains an assert.
        """
        out: List[Vulnerability] = []
        for meth in methods:
            if not meth.is_method_decorated:
                continue
            body = meth.body
            # Skip bodies whose only conditional asserts live inside asProver —
            # O1JS_LOGIC_OUTSIDE_PROOF already covers that archetype.
            controlled = {
                p for i, p in enumerate(meth.params)
                if i < len(meth.param_types)
                and meth.param_types[i]
                and re.search(r"\bBool\b", meth.param_types[i] or "")
            }
            controlled |= _simple_aliases(body, controlled)
            # Locals assigned from `.toBoolean()` on a controlled Bool.
            for am in re.finditer(
                r"\b(?:const|let|var)\s+(\w+)\s*=\s*(\w+)\s*\.\s*toBoolean\s*\(\s*\)",
                body,
            ):
                if am.group(2) in controlled:
                    controlled.add(am.group(1))
            if not controlled:
                continue
            asserted = set()
            for am in re.finditer(
                r"\b(\w+)\s*\.\s*assert(?:True|False|Equals|Bool)\s*\(",
                body,
            ):
                asserted.add(am.group(1))
            n = len(body)
            for im in re.finditer(r"\bif\b", body):
                # Skip `if` inside asProver callbacks to avoid double-reporting.
                preceding = body[:im.start()]
                if _ASPROVER_CALL_RE.search(preceding):
                    # Cheap heuristic: if an asProver appears before this if and
                    # the nearest unmatched `{` depth from that asProver still
                    # encloses us, skip. Use paren+brace walk from last asProver.
                    last = None
                    for am in _ASPROVER_CALL_RE.finditer(preceding):
                        last = am
                    if last is not None:
                        args = _paren_segment(body, last.end() - 1)
                        cb = _first_callback_brace_body(args)
                        if cb is not None:
                            # Approximate: if the if offset falls within the
                            # asProver call span, treat as inside.
                            call_end = last.end() + len(args)
                            if last.start() <= im.start() <= call_end + 8:
                                continue
                j = im.end()
                depth = 0
                while j < n:
                    c = body[j]
                    if c in "([":
                        depth += 1
                    elif c in ")]":
                        depth -= 1
                    elif c == "{" and depth == 0:
                        break
                    j += 1
                if j >= n or body[j] != "{":
                    continue
                cond = body[im.end():j].strip()
                # Strip wrapping parens: `(flag)` / `(flag.toBoolean())`
                core = cond
                if core.startswith("(") and core.endswith(")"):
                    core = core[1:-1].strip()
                if core.startswith("!"):
                    core = core[1:].strip()
                to_bool = re.fullmatch(r"(\w+)\s*\.\s*toBoolean\s*\(\s*\)", core)
                if to_bool:
                    gate = to_bool.group(1)
                elif re.fullmatch(r"\w+", core):
                    gate = core
                else:
                    continue  # inline comparison — leave alone
                if gate not in controlled or gate in asserted:
                    continue
                block = _brace_segment(body, j)
                if not re.search(
                    r"\.(?:assertEquals|assertTrue|assertFalse|assertLessThan|"
                    r"assertLessThanOrEqual|assertGreaterThan|assertGreaterThanOrEqual|"
                    r"assertNotEquals|assertBool|requireEquals)\s*\("
                    r"|assertCanMint|assertCanBurn",
                    block,
                ):
                    continue
                line = meth.start_line + body.count("\n", 0, im.start())
                out.append(Vulnerability(
                    pattern_name="O1JS_CONDITIONAL_ASSERT",
                    severity=Severity.MEDIUM,
                    function=meth.name,
                    location=(line, 0),
                    origin_tier=O1JS_ORIGIN_TIER,
                    rule_id="O1JS_CONDITIONAL_ASSERT",
                    title=(
                        f"Assert gated by prover-controlled condition `{gate}` "
                        f"in `{meth.name}`"
                    ),
                    description=(
                        f"An assert runs inside `if {cond} {{ ... }}`, and `{gate}` is "
                        f"a prover-controlled `@method` Bool (or derived from one). A "
                        f"JS conditional does not constrain the circuit the way "
                        f"`Provable.if` does — the prover can choose the branch that "
                        f"skips the check. Enforce the constraint unconditionally "
                        f"(both branches), or derive the gate from constrained state."
                    ),
                    evidence={
                        "method": meth.name,
                        "condition": gate,
                        "framework": "o1js",
                    },
                ))
        return out

    # --- Rule 4: weak account permissions ---------------------------------

    def _detect_weak_permissions(self, src: str, stripped: str) -> List[Vulnerability]:
        out: List[Vulnerability] = []
        circuit_fields = ("editState", "send")
        upgrade_fields = ("setVerificationKey", "setPermissions")
        other_none_fields = ("receive", "setDelegate", "incrementNonce")
        for pm in re.finditer(r"permissions\s*\.\s*set\s*\(", stripped):
            seg = _paren_segment(stripped, pm.end() - 1)
            weak_circuit: List[Tuple[str, str]] = []
            findings_spec: List[Tuple[str, str, bool]] = []  # field, value, is_upgrade

            for field in circuit_fields + upgrade_fields + other_none_fields:
                m = re.search(
                    re.escape(field)
                    + r"\s*:\s*(?:Permissions|Permission)"
                    r"(?:\s*\.\s*VerificationKey)?\s*\.\s*"
                    r"(proofOrSignature|signature|none)\s*\(",
                    seg,
                )
                if not m:
                    continue
                weak = m.group(1)
                if field in circuit_fields and weak in ("proofOrSignature", "none"):
                    weak_circuit.append((field, weak))
                    findings_spec.append((field, weak, False))
                elif field in upgrade_fields and weak in (
                    "proofOrSignature", "signature", "none",
                ):
                    findings_spec.append((field, weak, True))
                elif field in other_none_fields and weak == "none":
                    findings_spec.append((field, weak, False))

            has_circuit_weak = bool(weak_circuit)
            line = _line_of(src, pm.start())
            for field, weak, is_upgrade in findings_spec:
                if is_upgrade:
                    sev = Severity.HIGH if has_circuit_weak else Severity.MEDIUM
                    title = (
                        f"Unlocked upgrade permission "
                        f"`{field}: Permissions.{weak}()`"
                    )
                    desc = (
                        f"`{field}` is set to `Permissions.{weak}()`. Mina documents "
                        f"this as a development training wheel: the account key can "
                        f"change the verification key or rewrite permissions (and "
                        f"therefore bypass every circuit gate). For a finalized "
                        f"zkApp set `{field}` to `Permissions.impossible()` (or "
                        f"`proof` with an explicit permissionless upgrade path)."
                    )
                else:
                    sev = (
                        Severity.HIGH
                        if (field in circuit_fields and weak == "none")
                        else Severity.MEDIUM
                    )
                    title = f"Weak account permission `{field}: Permissions.{weak}()`"
                    desc = (
                        f"`{field}` is set to `Permissions.{weak}()`. With "
                        f"`proofOrSignature`, a holder of the zkApp account's private key "
                        f"can change `{field}` by SIGNATURE, bypassing the `@method` proof "
                        f"logic entirely; `none` removes the gate outright. For a zkApp "
                        f"whose security depends on its circuits, `{field}` should be "
                        f"`Permissions.proof()`."
                    )
                evidence = {
                    "permission": field,
                    "value": weak,
                    "framework": "o1js",
                }
                if is_upgrade:
                    evidence["upgrade"] = True
                out.append(Vulnerability(
                    pattern_name="O1JS_WEAK_PERMISSIONS",
                    severity=sev,
                    function="",
                    location=(line, 0),
                    origin_tier=O1JS_ORIGIN_TIER,
                    rule_id="O1JS_WEAK_PERMISSIONS",
                    title=title,
                    description=desc,
                    evidence=evidence,
                ))
        return out


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

def _brace_segment(s: str, open_brace_idx: int) -> str:
    """Return the text inside the braces starting at ``open_brace_idx``."""
    if open_brace_idx >= len(s) or s[open_brace_idx] != "{":
        return ""
    depth = 0
    for i in range(open_brace_idx, len(s)):
        if s[i] == "{":
            depth += 1
        elif s[i] == "}":
            depth -= 1
            if depth == 0:
                return s[open_brace_idx + 1:i]
    return s[open_brace_idx + 1:]


def _first_callback_brace_body(args: str) -> Optional[Tuple[str, int]]:
    """Extract the first ``() => { ... }`` / ``function (...) { ... }`` body.

    Returns ``(body, brace_offset_in_args)`` or None when the callback is an
    expression arrow without a block (``() => x``) — those cannot contain
    multi-statement security logic and are left alone.
    """
    m = re.search(r"(?:=>\s*\{|\bfunction\b[^{]{0,%d}\{)" % _MAX_PARAMS, args)
    if not m:
        return None
    brace = args.find("{", m.start())
    if brace < 0:
        return None
    return _brace_segment(args, brace), brace


def _state_bound_locals(body: str, state: Dict[str, str]) -> Set[str]:
    """Locals assigned from ``this.<state>.getAndRequireEquals()`` / ``.get()``."""
    bound: Set[str] = set()
    for am in re.finditer(
        r"\b(?:const|let|var)\s+(\w+)\s*=\s*this\s*\.\s*(\w+)\s*\.\s*"
        r"(?:getAndRequireEquals|getAndAssertEquals|get)\s*\(", body,
    ):
        if am.group(2) in state:
            bound.add(am.group(1))
    return bound


def _simple_aliases(body: str, seeds: Set[str]) -> Set[str]:
    """Same-body aliases created by plain identifier assignments.

    Deliberately narrow: ``const q = amount;`` and ``let q: UInt64 = amount;``
    join the alias set, but expressions such as ``amount.add(1)`` do not. This
    catches common readability aliases without pretending to be dataflow.
    """
    aliases = set(seeds)
    if not aliases:
        return aliases
    lets = [
        (m.group(1), m.group(2))
        for m in re.finditer(
            r"\b(?:const|let|var)\s+(\w+)(?:\s*:\s*[^=;]+)?\s*=\s*(\w+)\s*;",
            body,
        )
    ]
    changed = True
    while changed:
        changed = False
        for lhs, rhs in lets:
            if lhs in aliases or lhs.startswith("_"):
                continue
            if rhs in aliases:
                aliases.add(lhs)
                changed = True
    return aliases


def _account_update_locals(body: str) -> Set[str]:
    """Locals initialized from ``AccountUpdate.create*``.

    This keeps account-update send detection narrow: ``au.send(...)`` is a
    modeled token/account-update transfer only when ``au`` is visibly created
    by o1js in the same method body.
    """
    return {
        m.group(1)
        for m in re.finditer(
            r"\b(?:const|let|var)\s+(\w+)(?:\s*:\s*[^=;]+)?\s*=\s*"
            r"AccountUpdate\s*\.\s*create(?:Signed)?\s*\(",
            body,
        )
    }


def _arg_root_ident(arg: str) -> Optional[str]:
    """Leading identifier of a call argument (before ``.`` / ``[`` / ``(``)."""
    m = re.match(r"\s*(\w+)", arg or "")
    return m.group(1) if m else None


def _is_proof_type(type_str: Optional[str]) -> bool:
    """True for ``Proof<...>``, ``SelfProof<...>``, ``DynamicProof<...>``,
    or an identifier ending in ``Proof`` (ZkProgram proof-class convention)."""
    if not type_str:
        return False
    t = type_str.strip()
    if re.match(r"^(?:Proof|SelfProof|DynamicProof)\s*<", t):
        return True
    base = re.match(r"^(\w+)", t)
    return bool(base and base.group(1).endswith("Proof"))


def _proof_has_unconditional_verify(body: str, param: str) -> bool:
    """True if ``param.verify(...)`` appears in body."""
    return bool(re.search(
        r"\b" + re.escape(param) + r"\s*\.\s*verify\s*\(", body,
    ))


def _proof_has_verify_if(body: str, param: str) -> bool:
    """True if ``param.verifyIf(...)`` appears in body."""
    return bool(re.search(
        r"\b" + re.escape(param) + r"\s*\.\s*verifyIf\s*\(", body,
    ))


def _proof_public_fields_used(body: str, param: str) -> bool:
    """True if a proof's public input/output is read in this method body."""
    return bool(re.search(
        r"\b" + re.escape(param) + r"\s*\.\s*public(?:Input|Output)\b", body,
    ))


def _unsafe_proof_verify_if(
    body: str, param: str, method_params: List[str], state_bound: Set[str],
) -> Optional[Tuple[str, int]]:
    """A ``verifyIf`` gated by an unconstrained method parameter.

    Returns ``(condition, offset)`` only for the narrow high-signal case where
    the root condition is a private ``@method`` argument or its simple alias,
    and that condition is not otherwise asserted/bound in the method body.
    """
    param_aliases = {p: _simple_aliases(body, {p}) for p in method_params}
    for m in re.finditer(r"\b" + re.escape(param) + r"\s*\.\s*verifyIf\s*\(", body):
        cond = _paren_segment(body, m.end() - 1).strip()
        root = _arg_root_ident(cond)
        if not root:
            continue
        for original, aliases in param_aliases.items():
            if original == param:
                continue
            if root not in aliases:
                continue
            # If the condition/alias is itself constrained (e.g.
            # ``shouldVerify.assertTrue()``), verifyIf is effectively forced.
            if O1jsLexer._asserts_on(body, aliases, state_bound) != "none":
                continue
            return (cond[:80], m.start())
    return None


def _proof_settled_via_offchain_state(body: str, param: str) -> bool:
    """True if ``this.offchainState.settle(<param>)`` appears in body.

    The Mina OffchainState API verifies the recursive settlement proof inside
    ``settle`` — the contract method is documented as a one-liner that only
    forwards the proof. Matching ANY ``.settle(param)`` would hide true
    positives on hand-rolled settle helpers that never verify, so this is
    intentionally narrowed to the ``offchainState`` receiver name.
    """
    return bool(re.search(
        r"this\s*\.\s*offchainState\s*\.\s*settle\s*\(\s*"
        + re.escape(param)
        + r"\s*\)",
        body,
    ))


def _split_statements(body: str) -> List[Tuple[str, int]]:
    """Split ``body`` into top-level statements on ``;`` (not on newlines).

    Respects nested parens/brackets/braces so multi-line chains like
    ``amount\\n  .lessThanOrEqual(balance)\\n  .assertTrue();`` stay one
    statement. Returns ``(statement_text, start_offset)`` pairs. Template
    literals / strings are already blanked by ``_strip_comments`` before
    method bodies are extracted.
    """
    out: List[Tuple[str, int]] = []
    depth = 0
    start = 0
    i = 0
    n = len(body)
    while i < n:
        ch = body[i]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
        elif ch == ";" and depth == 0:
            out.append((body[start:i], start))
            start = i + 1
        i += 1
    if start < n and body[start:].strip():
        out.append((body[start:], start))
    return out


def _matching_paren_end(s: str, open_paren_idx: int) -> Optional[int]:
    """Index of the ``)`` matching ``s[open_paren_idx]``, or None."""
    if open_paren_idx >= len(s) or s[open_paren_idx] != "(":
        return None
    depth = 0
    for i in range(open_paren_idx, len(s)):
        if s[i] == "(":
            depth += 1
        elif s[i] == ")":
            depth -= 1
            if depth == 0:
                return i
    return None


def _has_top_level_assign(s: str) -> bool:
    """True if ``s`` contains a top-level ``=`` (not ``==``/``!=``/``<=``/``=>``)."""
    depth = 0
    i = 0
    n = len(s)
    while i < n:
        ch = s[i]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
        elif ch == "=" and depth == 0:
            prev = s[i - 1] if i > 0 else ""
            nxt = s[i + 1] if i + 1 < n else ""
            if prev in "=!<>":
                i += 1
                continue
            if nxt == "=":
                i += 1
                continue
            if nxt == ">":  # arrow
                i += 1
                continue
            return True
        i += 1
    return False


def _arg_is_unconstrained_sender(arg: str, tainted: Set[str]) -> bool:
    """True if a call argument is the witnessed sender (local or inline)."""
    if not arg or not arg.strip():
        return False
    a = arg.strip()
    if _SENDER_UNCONSTRAINED_RE.search(a):
        return True
    root = _arg_root_ident(a)
    return bool(root and root in tainted)


def _sender_authenticated_via_account_update(body: str, tainted: Set[str]) -> bool:
    """True if the witnessed sender is passed to AccountUpdate.createSigned
    (or AccountUpdate.create(...).requireSignature() / a local AU with
    .requireSignature()). Argument identity is required — a createSigned on
    a different key must NOT suppress."""
    # AccountUpdate.createSigned(<sender>[, ...])
    for m in re.finditer(r"AccountUpdate\s*\.\s*createSigned\s*\(", body):
        seg = _paren_segment(body, m.end() - 1)
        parts = _split_top_level(seg, ",")
        if parts and _arg_is_unconstrained_sender(parts[0], tainted):
            return True

    # AccountUpdate.create(<sender>)....requireSignature()
    for m in re.finditer(r"AccountUpdate\s*\.\s*create\s*\(", body):
        open_paren = m.end() - 1
        close = _matching_paren_end(body, open_paren)
        if close is None:
            continue
        seg = body[open_paren + 1:close]
        parts = _split_top_level(seg, ",")
        if not parts or not _arg_is_unconstrained_sender(parts[0], tainted):
            continue
        # Chained: AccountUpdate.create(sender).requireSignature()
        after = body[close + 1: close + 1 + 80]
        if re.match(r"\s*\.\s*requireSignature\s*\(", after):
            return True
        # Assigned: const au = AccountUpdate.create(sender); ... au.requireSignature()
        # Look backward from this create for a binding name.
        prefix = body[max(0, m.start() - 80):m.start()]
        bm = re.search(
            r"\b(?:const|let|var)\s+(\w+)\s*=\s*$", prefix
        )
        if bm:
            au_name = bm.group(1)
            if re.search(
                r"\b" + re.escape(au_name) + r"\s*\.\s*requireSignature\s*\(", body
            ):
                return True
    return False


def _sender_unconstrained_is_load_bearing(body: str, tainted: Set[str]) -> bool:
    """True if getUnconstrained (or a local from it) appears in assert/set/send."""
    # Spans that make an unconstrained sender load-bearing (and vacuous).
    spans: List[Tuple[int, int]] = []
    for m in re.finditer(
        r"(?:assertEquals|assertTrue|assertFalse|assertNotEquals|"
        r"requireEquals|assert)\s*\(",
        body,
    ):
        end = _matching_paren_end(body, m.end() - 1)
        if end is not None:
            spans.append((m.start(), end + 1))
    for m in re.finditer(r"this\s*\.\s*\w+\s*\.\s*set\s*\(", body):
        end = _matching_paren_end(body, m.end() - 1)
        if end is not None:
            spans.append((m.start(), end + 1))
    for m in re.finditer(r"this\s*\.\s*send\s*\(", body):
        end = _matching_paren_end(body, m.end() - 1)
        if end is not None:
            spans.append((m.start(), end + 1))

    def _in_span(pos: int) -> bool:
        return any(a <= pos < b for a, b in spans)

    for m in _SENDER_UNCONSTRAINED_RE.finditer(body):
        if _in_span(m.start()):
            return True
    for name in tainted:
        for m in re.finditer(r"\b" + re.escape(name) + r"\b", body):
            if _in_span(m.start()):
                return True
    return False


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


def analyze_file(
    filepath: str,
    source: str,
    include_tests: bool = False,
    include_examples: bool = False,
) -> List[Vulnerability]:
    """Analyze a single file's ``source`` text. Dispatches to the Noir analyzer
    for ``.nr`` files and the o1js analyzer otherwise.

    Path policy applies to BOTH backends: test files are suppressed unless
    ``include_tests``, and example files are downgraded to LOW unless
    ``include_examples`` (see :mod:`o1js_scan.paths`).
    """
    from .paths import apply_example_policy, is_test_path

    if not include_tests and is_test_path(filepath):
        return []
    if str(filepath).endswith(".nr"):
        from .noir import NoirLexer
        vulns = NoirLexer(include_tests=include_tests).analyze(source, Path(filepath))
    else:
        vulns = O1jsLexer().analyze(source, Path(filepath))
    vulns, _n = apply_example_policy(filepath, vulns, include_examples)
    return vulns


# Directory basenames skipped when walking a project tree. Keep this list
# documented in the README — Noir CI trees often have ``target/`` from nargo.
_SKIP_DIR_NAMES = frozenset({
    "node_modules", ".git", "target", "dist", "build",
    "__pycache__", ".venv", "venv",
})

_O1JS_GLOBS = ("*.ts", "*.js", "*.mjs")
_NOIR_GLOBS = ("*.nr",)


def _path_is_skipped(path: Path) -> bool:
    return any(part in _SKIP_DIR_NAMES for part in path.parts)


def analyze_project(
    root: str,
    lang: str = "auto",
    include_tests: bool = False,
    include_examples: bool = False,
    stats: "Optional[ScanStats]" = None,
) -> List[Tuple[str, Vulnerability]]:
    """Scan o1js (``.ts``/``.js``/``.mjs``) and/or Noir (``.nr``) files under
    ``root``.

    ``lang`` is ``auto`` (both), ``o1js``, or ``noir``. Skips ``node_modules``,
    ``target``, ``.git``, and other build/vendor directory basenames. Returns
    ``[(filepath, vuln), ...]``.
    """
    from .noir import NoirLexer, is_noir_source
    from .paths import ScanStats, apply_example_policy, is_test_path

    if stats is None:
        stats = ScanStats()
    lang = (lang or "auto").lower()
    if lang not in ("auto", "o1js", "noir"):
        raise ValueError(f"lang must be auto|o1js|noir, got {lang!r}")

    o1js_lexer = O1jsLexer()
    noir_lexer = NoirLexer(include_tests=include_tests)
    out: List[Tuple[str, Vulnerability]] = []
    base = Path(root)
    globs: List[str] = []
    if lang in ("auto", "o1js"):
        globs.extend(_O1JS_GLOBS)
    if lang in ("auto", "noir"):
        globs.extend(_NOIR_GLOBS)

    if base.is_file():
        paths = [base]
    else:
        paths = [
            p for pat in globs
            for p in base.rglob(pat)
            if not _path_is_skipped(p)
        ]

    for p in paths:
        sp = str(p)
        # Test code is skipped before it is even read: the finding would be the
        # point of the test, not a bug. Counted so the CLI can say so out loud.
        if not include_tests and is_test_path(sp):
            stats.skipped_test_files += 1
            continue
        try:
            src = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        found: List[Vulnerability] = []
        if sp.endswith(".nr"):
            if lang == "o1js":
                continue
            if is_noir_source(src, sp):
                found = noir_lexer.analyze(src, p)
        elif lang != "noir" and is_o1js_source(src, sp):
            found = o1js_lexer.analyze(src, p)
        if not found:
            continue
        found, n_down = apply_example_policy(sp, found, include_examples)
        stats.downgraded_example_findings += n_down
        for v in found:
            out.append((sp, v))
    return out
