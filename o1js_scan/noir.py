"""Noir circuit soundness analyzer — lexical, dependency-free.

Same soundness DNA as the o1js scanner (under-constrained witnesses), applied
to `Noir <https://noir-lang.org>`_ circuits (``.nr`` files). Noir is Aztec's
Rust-like ZK DSL; the security-critical bugs are, as in Circom and o1js, in the
circuit author's own constraints — values a malicious prover controls that the
circuit never binds.

The marquee Noir footgun is the **unconstrained result**. Calling an
``unconstrained fn`` (an oracle / Brillig hint) from constrained code must be
wrapped in an ``unsafe { ... }`` block, and the value it returns is *only a
prover hint* — a malicious prover can return anything. It is sound only if the
circuit re-derives and asserts it, e.g.::

    // Safety: verified below
    let z = unsafe { inverse_hint(x) };
    assert(x * z == 1);   // <-- binds the hint; without this, z is free

This module flags an ``unsafe`` result that is never re-constrained. It is the
direct analog of the o1js ``O1JS_UNCONSTRAINED_PROVABLE_WITNESS`` rule.

Lexical only — regex over brace/paren structure, no AST or dataflow — matching
the rest of this tool. Findings are a starting point for human review.
Env kill-switch: ``AUDIT_NOIR_LEXER=0``.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import List, Optional, Set, Tuple

from .lexer import (
    _apply_suppressions,
    _line_of,
    _paren_segment,
    _split_top_level,
    _strip_comments,
)
from .vuln import Severity, Vulnerability

# Tier bucket stamped onto every finding this module emits.
NOIR_ORIGIN_TIER = "noir"

_NOIR_EXTS = (".nr",)
_NON_NOIR_EXTS = (".ts", ".js", ".mjs", ".sol", ".py", ".go", ".rs")

_IDENT_RE = re.compile(r"[A-Za-z_]\w*")


def is_noir_source(content: str, filepath: str = "") -> bool:
    """True if ``content`` is a Noir source file worth analyzing."""
    if filepath.endswith(_NOIR_EXTS):
        return True
    if filepath.endswith(_NON_NOIR_EXTS):
        return False
    # No decisive extension: look for Noir-shaped code.
    return bool(
        re.search(r"\bfn\s+\w+\s*\(", content)
        and re.search(r"\bassert(?:_eq)?\s*\(|\bunconstrained\s+fn\b|\bunsafe\s*\{"
                      r"|->\s*pub\b", content)
    )


# ---------------------------------------------------------------------------
# Brace-balanced function-body extraction
# ---------------------------------------------------------------------------

def _functions(stripped: str) -> List[Tuple[str, str, int]]:
    """Return ``[(name, body, body_start_offset), ...]`` for every ``fn`` with a
    body. Offsets index into ``stripped`` (length-preserving vs. the source, so
    they map straight back to line numbers)."""
    out: List[Tuple[str, str, int]] = []
    n = len(stripped)
    for m in re.finditer(r"\b(?:unconstrained\s+)?fn\s+(\w+)", stripped):
        i = m.end()
        # advance to the parameter list's '('
        while i < n and stripped[i] not in "({;":
            i += 1
        if i >= n or stripped[i] != "(":
            continue
        # balance the parameter parens
        depth = 0
        while i < n:
            c = stripped[i]
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    i += 1
                    break
            i += 1
        # skip an optional `-> ReturnType` up to the body's '{'
        while i < n and stripped[i] not in "{;":
            i += 1
        if i >= n or stripped[i] != "{":
            continue
        open_idx = i
        depth = 0
        while i < n:
            c = stripped[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        out.append((m.group(1), stripped[open_idx + 1:i], open_idx + 1))
    return out


def _idents(text: str) -> Set[str]:
    return set(_IDENT_RE.findall(text))


def _trailing_expr(body: str) -> str:
    """The implicit-return expression of a Noir body: the text after the last
    top-level ``;`` (Noir returns the trailing expression of a block)."""
    depth = 0
    last = -1
    for i, c in enumerate(body):
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == ";" and depth == 0:
            last = i
    return body[last + 1:]


def _top_level_statements(body: str) -> List[Tuple[str, int, bool]]:
    """Split ``body`` into ``(text, start_offset, terminated)`` statements at
    depth-0 ``;``. ``terminated`` is False for the trailing expression (the
    block's implicit return), which is not a discarded statement."""
    out: List[Tuple[str, int, bool]] = []
    depth = 0
    start = 0
    for i, c in enumerate(body):
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == ";" and depth == 0:
            out.append((body[start:i], start, True))
            start = i + 1
    if start < len(body) and body[start:].strip():
        out.append((body[start:], start, False))
    return out


def _has_eq_comparison(text: str) -> bool:
    """True if ``text`` contains a depth-0 ``==``/``!=``/``<=``/``>=`` operator
    (the unambiguous comparisons — never generics or shifts)."""
    depth = 0
    for i in range(len(text) - 1):
        c = text[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif depth == 0 and text[i:i + 2] in ("==", "!=", "<=", ">="):
            return True
    return False


def _has_any_comparison(text: str) -> bool:
    """Lenient: any depth-0 comparison, including bare ``<``/``>`` (but not
    ``::<`` generics or ``<<``/``>>`` shifts). Used only to widen reachability."""
    if _has_eq_comparison(text):
        return True
    depth = 0
    n = len(text)
    for i, c in enumerate(text):
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif depth == 0 and c in "<>":
            prev = text[i - 1] if i > 0 else ""
            nxt = text[i + 1] if i + 1 < n else ""
            if prev not in ":<>" and nxt not in "<>":
                return True
    return False


def _reachable_to_constraint_or_output(body: str) -> Set[str]:
    """Identifiers in ``body`` that flow into a constraint (`assert`/`assert_eq`),
    any comparison, or the returned value, expanded to a fixpoint through `let`
    bindings. An input NOT in this set influences neither a check nor the output.
    (Comparisons are included so a discarded-comparison input is diagnosed by
    the more specific NOIR_UNASSERTED_BOOL rule, not double-reported here.)"""
    seed: Set[str] = set()
    for am in re.finditer(r"\bassert(?:_eq)?\s*\(", body):
        seed |= _idents(_paren_segment(body, am.end() - 1))
    for rm in re.finditer(r"\breturn\b([^;]{0,4000});", body):
        seed |= _idents(rm.group(1))
    seed |= _idents(_trailing_expr(body))
    for stmt, _off, _term in _top_level_statements(body):
        if _has_any_comparison(stmt):
            seed |= _idents(stmt)
    # `if` conditions influence which constraints apply — count them as uses so
    # a control-flow-only input is diagnosed by NOIR_CONDITIONAL_ASSERT, not here.
    for cm in re.finditer(r"\bif\b([^{;]{0,300})\{", body):
        seed |= _idents(cm.group(1))

    lets = [(m.group(1), m.group(2)) for m in re.finditer(
        r"\blet\s+(?:mut\s+)?(\w+)\s*=\s*([^;]{0,4000});", body)]
    changed = True
    while changed:
        changed = False
        for name, rhs in lets:
            if name in seed:
                for idt in _idents(rhs):
                    if idt not in seed:
                        seed.add(idt)
                        changed = True
    return seed


def _controlled_witnesses(stripped: str) -> Set[str]:
    """Prover-controlled value sources the tool models: private `main` inputs
    and `unsafe {}` results (excluding `_`-prefixed names)."""
    controlled = {
        n for n, is_pub in _main_params(stripped)
        if not is_pub and not n.startswith("_")
    }
    for um in re.finditer(r"\blet\s+(?:mut\s+)?([\w(),\s]{0,200}?)\s*=\s*unsafe\s*\{", stripped):
        controlled |= {w for w in re.findall(r"\w+", um.group(1))
                       if w != "mut" and not w.startswith("_")}
    return controlled


def _main_params(stripped: str) -> List[Tuple[str, bool]]:
    """Parameters of ``fn main`` as ``[(name, is_public), ...]``. A Noir input is
    public when its type is prefixed with ``pub`` (``x: pub Field``)."""
    m = re.search(r"\bfn\s+main\s*\(([^)]{0,2000})\)", stripped)
    if not m:
        return []
    out: List[Tuple[str, bool]] = []
    for part in _split_top_level(m.group(1), ","):
        part = part.strip()
        if not part or ":" not in part:
            continue
        name, _, typ = part.partition(":")
        name = re.sub(r"^\s*mut\s+", "", name).strip()
        if re.fullmatch(r"\w+", name):
            out.append((name, bool(re.match(r"\s*pub\b", typ))))
    return out


# ---------------------------------------------------------------------------
# Lexer
# ---------------------------------------------------------------------------

class NoirLexer:
    """Lexical soundness analyzer for Noir circuit source."""

    def analyze(self, content: str, file_path: Optional[Path] = None) -> List[Vulnerability]:
        if os.environ.get("AUDIT_NOIR_LEXER", "1") == "0":
            return []
        if not is_noir_source(content, str(file_path or "")):
            return []

        stripped = _strip_comments(content)
        vulns: List[Vulnerability] = []
        for name, body, offset in _functions(stripped):
            vulns += self._detect_unconstrained_unsafe(content, body, offset, name)
        vulns += self._detect_unconstrained_input(content, stripped)
        vulns += self._detect_unchecked_cast(content, stripped)
        for name, body, offset in _functions(stripped):
            vulns += self._detect_unasserted_bool(content, body, offset, name)
        vulns += self._detect_conditional_assert(content, stripped)
        vulns += self._detect_unsafe_missing_safety(content, stripped)
        return _apply_suppressions(content, vulns)

    # --- Rule 1: unconstrained `unsafe {}` result -------------------------

    def _detect_unconstrained_unsafe(
        self, src: str, body: str, body_offset: int, fn_name: str,
    ) -> List[Vulnerability]:
        # Identifiers that ARE bound by a constraint in this function body:
        # seed from assert/assert_eq arguments, then walk backward through simple
        # `let name = rhs;` bindings until the constrained set reaches a
        # fixpoint. This mirrors `_reachable_to_constraint_or_output` so an
        # unsafe hint re-derived through multiple locals is treated as bound.
        constrained: Set[str] = set()
        for am in re.finditer(r"\bassert(?:_eq)?\s*\(", body):
            constrained |= _idents(_paren_segment(body, am.end() - 1))

        lets = [(m.group(1), m.group(2)) for m in re.finditer(
            r"\blet\s+(?:mut\s+)?(\w+)\s*=\s*([^;]{0,4000});", body)]
        changed = True
        while changed:
            changed = False
            for name, rhs in lets:
                if name in constrained:
                    for idt in _idents(rhs):
                        if idt not in constrained:
                            constrained.add(idt)
                            changed = True

        out: List[Vulnerability] = []
        for um in re.finditer(r"\blet\s+(?:mut\s+)?([\w(),\s]{0,200}?)\s*=\s*unsafe\s*\{", body):
            # binding names, dropping `mut` and `_`-prefixed (intentionally unused)
            names = [w for w in re.findall(r"\w+", um.group(1))
                     if w != "mut" and not w.startswith("_")]
            free = [w for w in names if w not in constrained]
            if not free:
                continue
            line = _line_of(src, body_offset + um.start())
            witness = free[0]
            out.append(Vulnerability(
                pattern_name="NOIR_UNCONSTRAINED_WITNESS",
                severity=Severity.HIGH,
                function=fn_name,
                location=(line, 0),
                origin_tier=NOIR_ORIGIN_TIER,
                rule_id="NOIR_UNCONSTRAINED_WITNESS",
                title=f"Unconstrained `unsafe` result `{witness}` in `{fn_name}`",
                description=(
                    f"`{witness}` is bound from an `unsafe {{ ... }}` block — the result of "
                    f"an unconstrained function (oracle / Brillig hint) — and is never "
                    f"re-constrained by an `assert` / `assert_eq` in `{fn_name}`. The "
                    f"unconstrained callback runs OUTSIDE the circuit, so a malicious prover "
                    f"can return any value. Re-derive and assert it in-circuit "
                    f"(e.g. `assert(x * {witness} == 1)`), the way a correct Noir circuit "
                    f"binds an oracle result. Direct analog of an under-constrained signal."
                ),
                evidence={
                    "witness": witness, "function": fn_name,
                    "witness_source": "unsafe", "framework": "noir",
                },
            ))
        return out

    # --- Rule 2: private circuit input bound to nothing -------------------

    def _detect_unconstrained_input(self, src: str, stripped: str) -> List[Vulnerability]:
        params = _main_params(stripped)
        if not params:
            return []
        body = None
        for name, b, _off in _functions(stripped):
            if name == "main":
                body = b
                break
        if body is None:
            return []
        reachable = _reachable_to_constraint_or_output(body)

        out: List[Vulnerability] = []
        sig = re.search(r"\bfn\s+main\s*\(", stripped)
        line = _line_of(src, sig.start()) if sig else 0
        for name, is_pub in params:
            # public inputs are already bound (they're part of the statement);
            # `_`-prefixed params are conventionally intentionally-unused.
            if is_pub or name.startswith("_") or name in reachable:
                continue
            out.append(Vulnerability(
                pattern_name="NOIR_UNCONSTRAINED_INPUT",
                severity=Severity.MEDIUM,
                function="main",
                location=(line, 0),
                origin_tier=NOIR_ORIGIN_TIER,
                rule_id="NOIR_UNCONSTRAINED_INPUT",
                title=f"Private input `{name}` is never constrained in `main`",
                description=(
                    f"`{name}` is a private (witness) input of the circuit `main`, but it "
                    f"flows into no `assert` / `assert_eq` and is not part of the public "
                    f"output. The proof therefore binds nothing about `{name}` — a classic "
                    f"forgotten-constraint bug (the prover can pick any value). Constrain it "
                    f"(e.g. `assert(hash({name}) == commitment)`) or expose it in the output, "
                    f"or drop the input. Direct analog of an under-constrained signal."
                ),
                evidence={
                    "witness": name, "function": "main",
                    "witness_source": "private_input", "framework": "noir",
                },
            ))
        return out

    # --- Rule 3: narrowing cast of an unbounded witness -------------------

    @staticmethod
    def _has_range_bound(text: str, ident: str) -> bool:
        """True if ``ident`` is range-constrained in ``text`` — a comparison
        assertion (`assert(ident < N)`), or an explicit bit-size assertion."""
        a = re.escape(ident)
        if re.search(r"\b" + a + r"\s*\.\s*assert(?:_max)?_bit_size\b", text):
            return True
        for am in re.finditer(r"\bassert(?:_eq)?\s*\(", text):
            seg = _paren_segment(text, am.end() - 1)
            if re.search(r"\b" + a + r"\b", seg) and re.search(r"[<>]=?", seg):
                return True
        return False

    def _detect_unchecked_cast(self, src: str, stripped: str) -> List[Vulnerability]:
        # Prover-controlled value sources this tool already models: private
        # `main` inputs and `unsafe {}` results. Scoping the rule to these keeps
        # it high-signal (loop counters / known-small locals are not flagged).
        controlled: Set[str] = {
            n for n, is_pub in _main_params(stripped)
            if not is_pub and not n.startswith("_")
        }
        for um in re.finditer(r"\blet\s+(?:mut\s+)?([\w(),\s]{0,200}?)\s*=\s*unsafe\s*\{", stripped):
            controlled |= {w for w in re.findall(r"\w+", um.group(1))
                           if w != "mut" and not w.startswith("_")}
        if not controlled:
            return []

        out: List[Vulnerability] = []
        seen: Set[Tuple[str, int]] = set()
        # narrowing casts to a small unsigned type truncate (take the low bits)
        for cm in re.finditer(r"\b([A-Za-z_]\w*)\s+as\s+(u8|u16|u32)\b", stripped):
            ident, ty = cm.group(1), cm.group(2)
            if ident not in controlled or self._has_range_bound(stripped, ident):
                continue
            line = _line_of(src, cm.start())
            if (ident, line) in seen:
                continue
            seen.add((ident, line))
            out.append(Vulnerability(
                pattern_name="NOIR_UNCHECKED_CAST",
                severity=Severity.MEDIUM,
                function="",
                location=(line, 0),
                origin_tier=NOIR_ORIGIN_TIER,
                rule_id="NOIR_UNCHECKED_CAST",
                title=f"Narrowing cast `{ident} as {ty}` without a range check",
                description=(
                    f"`{ident}` is a prover-controlled value (a private input or an "
                    f"`unsafe` result) cast to `{ty}` with no range assertion. A cast to a "
                    f"smaller unsigned type TRUNCATES (keeps the low bits) — it does NOT "
                    f"prove the original fits — so a prover can supply a large `{ident}` "
                    f"whose low bits pass while the true value differs. Range-check "
                    f"`{ident}` before the cast (e.g. `assert({ident} < BOUND)` or an "
                    f"explicit bit-size assertion). Analog of o1js `MissingRangeCheck`."
                ),
                evidence={
                    "witness": ident, "cast_to": ty,
                    "witness_source": "narrowing_cast", "framework": "noir",
                },
            ))
        return out

    # --- Rule 4: discarded comparison (unasserted Bool) -------------------

    _STMT_KEYWORDS = (
        "let", "assert", "return", "for", "if", "else", "while", "loop",
        "unsafe", "break", "continue", "constrain", "fn", "mut",
    )

    def _detect_unasserted_bool(
        self, src: str, body: str, body_offset: int, fn_name: str,
    ) -> List[Vulnerability]:
        out: List[Vulnerability] = []

        # (a) a comparison evaluated as a statement and discarded
        for stmt, off, terminated in _top_level_statements(body):
            if not terminated:
                continue  # trailing expression is the return value, not discarded
            s = stmt.strip()
            if not s or s.startswith(self._STMT_KEYWORDS):
                continue
            # an assignment (`x = ...`) is not a bare predicate
            if re.search(r"[^=!<>]=[^=]", s):
                continue
            if not _has_eq_comparison(s):
                continue
            line = _line_of(src, body_offset + off + (len(stmt) - len(stmt.lstrip())))
            out.append(Vulnerability(
                pattern_name="NOIR_UNASSERTED_BOOL",
                severity=Severity.HIGH,
                function=fn_name,
                location=(line, 0),
                origin_tier=NOIR_ORIGIN_TIER,
                rule_id="NOIR_UNASSERTED_BOOL",
                title=f"Comparison result discarded in `{fn_name}`",
                description=(
                    f"`{s[:60]}` is evaluated as a statement and thrown away. In Noir a "
                    f"comparison returns a `bool` and adds NO constraint on its own — the "
                    f"circuit computes the check and ignores the result, so it proves "
                    f"nothing. Wrap it in `assert(...)` (e.g. `assert({s[:40]});`). Analog of "
                    f"o1js `O1JS_UNASSERTED_BOOL`."
                ),
                evidence={"function": fn_name, "expr": s[:80], "framework": "noir"},
            ))

        # (b) a `let` bound to a comparison whose result is never used
        for lm in re.finditer(r"\blet\s+(?:mut\s+)?(\w+)\s*=\s*([^;]{0,4000});", body):
            name, rhs = lm.group(1), lm.group(2)
            if name.startswith("_") or not _has_eq_comparison(rhs):
                continue
            if len(re.findall(r"\b" + re.escape(name) + r"\b", body)) > 1:
                continue  # referenced elsewhere → used
            line = _line_of(src, body_offset + lm.start())
            out.append(Vulnerability(
                pattern_name="NOIR_UNASSERTED_BOOL",
                severity=Severity.MEDIUM,
                function=fn_name,
                location=(line, 0),
                origin_tier=NOIR_ORIGIN_TIER,
                rule_id="NOIR_UNASSERTED_BOOL",
                title=f"Unused comparison result `{name}` in `{fn_name}`",
                description=(
                    f"`{name}` holds a comparison result that is never asserted, returned, "
                    f"or otherwise used. The comparison constrains nothing — likely a "
                    f"forgotten `assert({name})`. Assert it or remove it. Analog of o1js "
                    f"`O1JS_UNASSERTED_BOOL`."
                ),
                evidence={"witness": name, "function": fn_name, "framework": "noir"},
            ))
        return out

    # --- Rule 5: constraint gated by a prover-controlled condition --------

    def _detect_conditional_assert(self, src: str, stripped: str) -> List[Vulnerability]:
        controlled = _controlled_witnesses(stripped)
        if not controlled:
            return []
        out: List[Vulnerability] = []
        n = len(stripped)
        for im in re.finditer(r"\bif\b", stripped):
            # condition text up to the block '{' (paren/bracket-depth aware)
            j = im.end()
            depth = 0
            while j < n:
                c = stripped[j]
                if c in "([":
                    depth += 1
                elif c in ")]":
                    depth -= 1
                elif c == "{" and depth == 0:
                    break
                j += 1
            if j >= n or stripped[j] != "{":
                continue
            cond = stripped[im.end():j].strip()
            # only the high-signal case: the gate is a BARE prover-controlled
            # bool (`if flag {` / `if !flag {`), which the prover just sets false
            # to skip the constraint. Comparisons (e.g. `if x != 0`) are usually
            # legitimate guards and are not flagged.
            core = cond[1:].strip() if cond.startswith("!") else cond
            if not re.fullmatch(r"\w+", core) or core not in controlled:
                continue
            # block body must actually contain a constraint
            depth = 0
            k = j
            while k < n:
                c = stripped[k]
                if c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        break
                k += 1
            block = stripped[j + 1:k]
            if not re.search(r"\bassert(?:_eq)?\s*\(", block):
                continue
            line = _line_of(src, im.start())
            out.append(Vulnerability(
                pattern_name="NOIR_CONDITIONAL_ASSERT",
                severity=Severity.MEDIUM,
                function="",
                location=(line, 0),
                origin_tier=NOIR_ORIGIN_TIER,
                rule_id="NOIR_CONDITIONAL_ASSERT",
                title=f"Constraint gated by prover-controlled condition `{core}`",
                description=(
                    f"An `assert` runs inside `if {cond} {{ ... }}`, and `{core}` is a "
                    f"prover-controlled value (a private input or `unsafe` result). In Noir "
                    f"a constraint inside a conditional is only enforced when the condition "
                    f"holds, so a prover can set `{core}` to skip the check entirely — the "
                    f"assertion binds nothing. Enforce the constraint unconditionally, or "
                    f"constrain `{core}` itself so the prover can't choose the branch."
                ),
                evidence={"condition": core, "framework": "noir"},
            ))
        return out

    # --- Rule 6: `unsafe {}` without a `// Safety:` note ------------------

    def _detect_unsafe_missing_safety(self, src: str, stripped: str) -> List[Vulnerability]:
        out: List[Vulnerability] = []
        for um in re.finditer(r"\bunsafe\s*\{", stripped):
            # Noir's own convention (and compiler lint) is a `// Safety:` comment
            # on the block or the enclosing statement. Look back a few lines in
            # the RAW source (comments are stripped in `stripped`).
            back = src[max(0, um.start() - 300):um.start()]
            if re.search(r"//\s*Safety\s*:", back, re.IGNORECASE):
                continue
            line = _line_of(src, um.start())
            out.append(Vulnerability(
                pattern_name="NOIR_UNSAFE_MISSING_SAFETY",
                severity=Severity.LOW,
                function="",
                location=(line, 0),
                origin_tier=NOIR_ORIGIN_TIER,
                rule_id="NOIR_UNSAFE_MISSING_SAFETY",
                title="`unsafe` block without a `// Safety:` comment",
                description=(
                    "An `unsafe {{ ... }}` block calls unconstrained code but has no "
                    "`// Safety:` comment explaining why its result is sound. This is "
                    "Noir's own convention (the compiler warns on it) and a review-hygiene "
                    "signal: every `unsafe` result must be re-constrained, and the Safety "
                    "note documents how. Informational — does not fail CI by default."
                ),
                evidence={"framework": "noir"},
            ))
        return out


def analyze_noir_file(filepath: str, source: str) -> List[Vulnerability]:
    """Analyze a single Noir file's ``source`` text."""
    return NoirLexer().analyze(source, Path(filepath))
