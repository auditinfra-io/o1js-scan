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

def _functions(stripped: str, unconstrained_only: bool = False) -> List[Tuple[str, str, int]]:
    """Return ``[(name, body, body_start_offset), ...]`` for every ``fn`` with a
    body. Offsets index into ``stripped`` (length-preserving vs. the source, so
    they map straight back to line numbers).

    ``unconstrained_only`` restricts the result to ``unconstrained fn`` bodies.
    """
    out: List[Tuple[str, str, int]] = []
    n = len(stripped)
    for m in re.finditer(r"\b(?P<unc>unconstrained\s+)?fn\s+(?P<name>\w+)", stripped):
        if unconstrained_only and not m.group("unc"):
            continue
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
        out.append((m.group("name"), stripped[open_idx + 1:i], open_idx + 1))
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


# ---------------------------------------------------------------------------
# Unconstrained-function context
# ---------------------------------------------------------------------------
#
# An `unconstrained fn` body is Brillig: it runs OUTSIDE the circuit and emits
# no constraints at all. Every rule below has the same premise — "a constraint
# that should exist is missing or ineffective" — and that premise is simply
# false there. A narrowing cast cannot be "missing a range check" when there is
# no circuit to under-constrain; a discarded comparison constrains nothing
# either way; an `assert` is a Brillig runtime check, not a constraint.
#
# Soundness of unconstrained code rests entirely on how the CALLER re-constrains
# the value it returns, which is what NOIR_UNCONSTRAINED_WITNESS checks at the
# `unsafe { ... }` call site in constrained code — that is unaffected here.
#
# This is an explicit deny-list rather than "suppress everything": a rule added
# later defaults to FIRING inside unconstrained code, which is the safe bias for
# a security tool. Add to this set only with the argument above in hand.
_UNCONSTRAINED_SUPPRESSED_RULES = frozenset({
    "NOIR_UNCHECKED_CAST",
    "NOIR_UNASSERTED_BOOL",
    "NOIR_VACUOUS_CONSTRAINT",
    "NOIR_CONDITIONAL_ASSERT",
    "NOIR_CONDITIONAL_CONSTRAIN",
    "NOIR_UNUSED_CHECK_RESULT",
    "NOIR_UNCONSTRAINED_WITNESS",
    "NOIR_UNSAFE_MISSING_SAFETY",
})
# NOIR_UNCONSTRAINED_INPUT / NOIR_UNCONSTRAINED_PUBLIC_INPUT are deliberately
# absent: they concern `fn main`, the circuit entry point, which cannot itself
# be `unconstrained`. Listing them would be a no-op that implied otherwise.


def _unconstrained_line_ranges(content: str, stripped: str) -> List[Tuple[int, int]]:
    """Inclusive ``(first_line, last_line)`` spans of every ``unconstrained fn``
    body. Uses the same paren/brace walk as :func:`_functions`, so array types
    in the signature (``[Field; N]``) do not truncate the span."""
    return [
        (_line_of(content, off), _line_of(content, off + len(body)))
        for _name, body, off in _functions(stripped, unconstrained_only=True)
    ]


# ---------------------------------------------------------------------------
# Test-context detection
# ---------------------------------------------------------------------------
#
# Noir tests deliberately build invalid values inside `unsafe` blocks to prove
# the surrounding asserts reject them, so an "unconstrained hint" in test code
# is the point of the test, not a circuit bug. Findings from test contexts are
# suppressed by default; `--include-tests` turns them back on.

_TEST_FILE_RE = re.compile(r"(?:^|/)(?:test_[^/]*\.nr|[^/]*_test\.nr)$")


def _is_test_path(filepath: str) -> bool:
    """True for ``*_test.nr`` / ``test_*.nr`` filenames, or any path under a
    ``test/`` or ``tests/`` directory."""
    p = str(filepath).replace("\\", "/")
    if _TEST_FILE_RE.search(p):
        return True
    return any(seg in ("test", "tests") for seg in p.split("/")[:-1])


def _matching_brace(text: str, open_idx: int) -> int:
    """Index of the ``}`` matching the ``{`` at ``open_idx`` (or end of text)."""
    depth = 0
    for i in range(open_idx, len(text)):
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
    return len(text) - 1


def _test_line_ranges(content: str, stripped: str) -> List[Tuple[int, int]]:
    """Inclusive ``(first_line, last_line)`` spans covering test code:

    * a ``mod test { ... }`` / ``mod tests { ... }`` block — block-scoped, since
      libraries commonly put one at the bottom of an otherwise production file;
    * a function carrying a ``#[test]`` / ``#[test(...)]`` attribute.
    """
    ranges: List[Tuple[int, int]] = []
    for m in re.finditer(r"\bmod\s+tests?\s*\{", stripped):
        close = _matching_brace(stripped, m.end() - 1)
        ranges.append((_line_of(content, m.start()), _line_of(content, close)))

    fn_spans = [(off, off + len(body)) for _n, body, off in _functions(stripped)]
    for m in re.finditer(r"#\s*\[\s*test\b[^\]]{0,200}\]", stripped):
        nxt = [(s, e) for s, e in fn_spans if s > m.end()]
        if nxt:
            start, end = min(nxt)
            ranges.append((_line_of(content, m.start()), _line_of(content, end)))
    return ranges


def _in_ranges(line: int, ranges: List[Tuple[int, int]]) -> bool:
    return any(lo <= line <= hi for lo, hi in ranges)


# Any call whose function name CONTAINS "assert", with optional turbofish:
#   assert(...)                      assert_eq(...)
#   assert_max_bit_size::<240>(...)  sortfn_assert(...)   my_assert(...)
# Noir's constraining vocabulary is far wider than assert/assert_eq, and
# user-supplied callbacks are conventionally named ``*_assert``. Matching the
# family (rather than a fixed alternation) is deliberately permissive; the
# paired tp_ mutation fixtures bound it by proving each rule still fires when
# the constraining construct is actually removed.
_ASSERT_CALL_RE = re.compile(r"\b\w*assert\w*\s*(?:::<[^>]{0,200}>)?\s*\(")


def _split_on_top_level_op(text: str, op: str) -> Optional[Tuple[str, str]]:
    """Split ``text`` at the first depth-0 occurrence of ``op``, or ``None``."""
    depth = 0
    n = len(text)
    for i in range(n - len(op) + 1):
        c = text[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif depth == 0 and text[i:i + len(op)] == op:
            return text[:i], text[i + len(op):]
    return None


def _norm_expr(text: str) -> str:
    """Whitespace-insensitive form, for comparing the two sides of an operator."""
    return re.sub(r"\s+", "", text)


# Operators that are trivially satisfied when both operands are the same
# expression. `!=`, `<` and `>` are deliberately excluded: those are always
# FALSE on identical operands, which makes the circuit unprovable — a liveness
# bug, not the silent soundness hole this rule is about.
_REFLEXIVE_OPS = ("==", ">=", "<=")


def _vacuous_reason(cond: str) -> Optional[Tuple[str, bool]]:
    """If ``cond`` is a trivially-true constraint, return ``(reason, is_typo)``.

    ``is_typo`` marks a self-comparison — a real check was clearly intended and
    got mistyped — as opposed to a constant, which is more often a placeholder.
    """
    e = _norm_expr(cond)
    if not e:
        return None
    if e == "true":
        return ("the condition is the constant `true`", False)
    for op in _REFLEXIVE_OPS:
        halves = _split_on_top_level_op(cond, op)
        if not halves:
            continue
        lhs, rhs = (_norm_expr(h) for h in halves)
        if lhs and lhs == rhs:
            return (f"both sides of `{op}` are the same expression `{lhs}`", True)
    return None


def _expr_start(text: str, end: int) -> int:
    """Index where the expression ending at ``end`` (exclusive) begins, walking
    left across balanced ``()``/``[]`` — e.g. the ``chunks[0]`` in
    ``chunks[0].assert_max_bit_size::<8>()``."""
    i = end - 1
    depth = 0
    while i >= 0:
        c = text[i]
        if c in ")]":
            depth += 1
        elif c in "([":
            if depth == 0:
                break
            depth -= 1
        elif depth == 0 and not (c.isalnum() or c in "_.:"):
            break
        i -= 1
    return i + 1


def _seed_from_asserts(text: str) -> Set[str]:
    """Identifiers constrained by assert-like calls in ``text``.

    Seeds from the argument list, and — for the METHOD form
    ``<receiver>.assert_xxx(...)`` — from the RECEIVER expression too, since
    that is the value being constrained::

        lt_parameter.assert_max_bit_size::<240>();   # constrains lt_parameter
    """
    seed: Set[str] = set()
    for am in _ASSERT_CALL_RE.finditer(text):
        seed |= _idents(_paren_segment(text, am.end() - 1))
        j = am.start() - 1
        while j >= 0 and text[j].isspace():
            j -= 1
        if j >= 0 and text[j] == ".":
            seed |= _idents(text[_expr_start(text, j):j])
    return seed


def _reachable_to_assert(body: str) -> Set[str]:
    """Identifiers that flow into an assert-family call only (fixpoint through
    ``let``, including tuple destructuring). Used for same-file helper
    summaries so a hollow ``confirm_*`` that only *returns* the hint does not
    credit the caller."""
    seed = _seed_from_asserts(body)
    # Expand through lets (including tuples) until fixpoint.
    _expand_constrained_through_lets(seed, body)
    return seed


def _reachable_to_constraint_or_output(body: str) -> Set[str]:
    """Identifiers in ``body`` that flow into a constraint (`assert`/`assert_eq`),
    any comparison, or the returned value, expanded to a fixpoint through `let`
    bindings. An input NOT in this set influences neither a check nor the output.
    (Comparisons are included so a discarded-comparison input is diagnosed by
    the more specific NOIR_UNASSERTED_BOOL rule, not double-reported here.)"""
    seed = _seed_from_asserts(body)
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

    # Tuple lets matter for ZKPassport / passport circuits:
    #   let (r, s) = split_array(dsc_signature);
    #   let (nullifier, ...) = nullify(..., salted_dg1, ...);
    # Without destructuring, inputs that only reach output via a helper return
    # never join the reachable set (false MEDIUM NOIR_UNCONSTRAINED_INPUT).
    _expand_constrained_through_lets(seed, body)
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


def _function_params(stripped: str, fn_name: str) -> List[str]:
    """Lexically parse parameter names for ``fn_name``. This intentionally
    mirrors ``_main_params`` but returns names only so helper-call summaries can
    map arguments by position without needing Noir type semantics.

    Supports Noir generics between the name and the parameter list
    (``fn confirm_hinted_notes<Note, let M: u32>(...)``).
    """
    m = re.search(
        r"\b(?:unconstrained\s+)?fn\s+"
        + re.escape(fn_name)
        + r"(?:\s*<[^;{]{0,800}?>)?\s*\(([^)]{0,4000})\)",
        stripped,
    )
    if not m:
        return []
    out: List[str] = []
    for part in _split_top_level(m.group(1), ","):
        part = part.strip()
        if not part or ":" not in part:
            continue
        name, _, _typ = part.partition(":")
        name = re.sub(r"^\s*mut\s+", "", name).strip()
        name = re.sub(r"^&\s*(?:mut\s+)?", "", name).strip()
        if re.fullmatch(r"\w+", name):
            out.append(name)
    return out


def _brace_segment(text: str, open_idx: int) -> str:
    """Return the interior of the ``{...}`` whose opening brace is at ``open_idx``."""
    if open_idx >= len(text) or text[open_idx] != "{":
        return ""
    depth = 0
    i = open_idx
    n = len(text)
    while i < n:
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1:i]
        i += 1
    return text[open_idx + 1:]


def _helper_constraint_summaries(stripped: str) -> dict:
    """Map helper name → parameter positions that the helper constrains.

    If the helper body contains any ``assert`` / ``assert_eq``, every parameter
    that appears as a whole word in the body is credited (Aztec helpers often
    rename params in loops before asserting). Helpers with **no** asserts are
    treated as hollow and credit nothing — miss-not-hide for return-only
    ``confirm_*`` stubs.
    """
    summaries: dict = {}
    for fn_name, helper_body, _off in _functions(stripped):
        helper_params = _function_params(stripped, fn_name)
        if not helper_params:
            continue
        if not _ASSERT_CALL_RE.search(helper_body):
            continue
        reachable_positions = {
            idx for idx, param in enumerate(helper_params)
            if re.search(r"\b" + re.escape(param) + r"\b", helper_body)
        }
        if reachable_positions:
            summaries[fn_name] = reachable_positions
    return summaries


# Call basenames that, by Aztec / Noir / ZKPassport convention, re-constrain an
# oracle hint even when the helper lives in another module (call site only).
# ``check_*`` covers passport integrity helpers (``check_dg1_sha256``,
# ``check_signed_attributes_*``, ``check_expiry``, …) — broader than membership
# alone. Hollow same-file ``confirm_*`` stubs are still filtered via summaries.
_CONSTRAINT_HELPER_NAME_RE = re.compile(
    r"\b(?:"
    r"constrain_\w+|confirm_\w+|verify_\w+"
    r"|check_\w+"
    r"|public_data_storage_read"
    r")\s*\("
)

# Subset used for unused-check-result. Bare ``verify_*`` / ``confirm_*`` /
# ``constrain_*`` calls are often unit side-effect helpers (assert inside) —
# only membership ``check_*`` bare discards and let-bound unused results fire.
_CHECK_RESULT_NAME_RE = re.compile(
    r"\b(?:"
    r"constrain_\w+|confirm_\w+|verify_\w+"
    r"|check_(?:non_)?membership\w*"
    r")\s*\("
)
_BARE_UNUSED_CHECK_RE = re.compile(
    r"\bcheck_(?:non_)?membership\w*\s*\("
)


def _let_bindings(body: str) -> List[Tuple[List[str], str]]:
    """Simple and tuple ``let`` bindings as ``[(names, rhs), ...]``.

    Tuple form matters for Aztec merkle proofs::

        let (ok, exists) = check_non_membership_with_hasher(..., witness, ...);
        assert(ok); assert(exists);

    Without destructuring, ``witness`` never joins the constrained set even though
    the asserted flags are exactly the proof that binds it.
    """
    out: List[Tuple[List[str], str]] = []
    # The optional ``: Type`` annotation must be tolerated or the fixpoint
    # breaks on ordinary code: ``let raw: Field = raw_transcript[i];`` used to
    # not match at all, orphaning ``raw_transcript`` from the assert that binds
    # it. The type alternation allows ``;`` only inside ``[...]`` so array types
    # (``[Field; N]``) parse without swallowing the next statement.
    for m in re.finditer(
        r"\blet\s+(?:mut\s+)?(\([^;]{0,400}?\)|\w+)\s*"
        r"(?::\s*(?:[^=;\[]|\[[^\]]{0,200}\]){0,200})?"
        r"=\s*([^;]{0,4000});",
        body,
    ):
        lhs, rhs = m.group(1), m.group(2)
        if lhs.startswith("("):
            names = [w for w in re.findall(r"\w+", lhs)
                     if w != "mut" and not w.startswith("_")]
        else:
            names = [lhs] if not lhs.startswith("_") else []
        if names:
            out.append((names, rhs))
    return out


def _expand_constrained_through_lets(constrained: Set[str], body: str) -> None:
    """Fixpoint: if any ``let`` name is constrained, add identifiers from its RHS."""
    lets = _let_bindings(body)
    changed = True
    while changed:
        changed = False
        for names, rhs in lets:
            if any(n in constrained for n in names):
                for idt in _idents(rhs):
                    if idt not in constrained:
                        constrained.add(idt)
                        changed = True


def _has_adjacent_safety_comment(src: str, unsafe_offset: int) -> bool:
    """True if a ``// Safety:`` note sits on the same line as ``unsafe`` or in
    the immediately preceding comment region (Noir / aztec-nr convention)."""
    return _adjacent_safety_comment_text(src, unsafe_offset) is not None


def _adjacent_safety_comment_text(src: str, unsafe_offset: int) -> Optional[str]:
    """Return the adjacent ``// Safety:`` comment block text, or ``None``.

    Walks upward from the line containing ``unsafe_offset``, skipping blank lines
    and a short ``let name =`` continuation (Aztec often splits
    ``let x =`` / ``unsafe { ... }`` across two lines with Safety above the let).
    """
    unsafe_line = _line_of(src, unsafe_offset)
    lines = src.splitlines()
    collected: List[str] = []
    line_text = lines[unsafe_line - 1] if 0 < unsafe_line <= len(lines) else ""

    same = re.search(r"//\s*Safety\s*:(.*)$", line_text, re.IGNORECASE)
    if same:
        collected.append(same.group(0))

    comment_lines_seen = 0
    skipped_let_continuation = False
    block: List[str] = []
    for prev in range(unsafe_line - 2, -1, -1):
        text = lines[prev].strip()
        if not text:
            continue
        if text.startswith("//"):
            comment_lines_seen += 1
            # Aztec-nr Safety notes can span a dozen lines; keep a hard cap so an
            # older unrelated Safety cannot bless a later unsafe.
            if comment_lines_seen > 20:
                break
            block.append(text)
            continue
        # Allow one `let name =` line between Safety and a following-line `unsafe`.
        if (
            not skipped_let_continuation
            and re.fullmatch(r"let\s+(?:mut\s+)?[\w(),\s]+=", text)
        ):
            skipped_let_continuation = True
            continue
        break
    block.reverse()
    joined = "\n".join(block)
    if re.search(r"^//\s*Safety\s*:", joined, re.IGNORECASE | re.MULTILINE):
        return joined
    if collected:
        return "\n".join(collected)
    return None


# Safety notes that document intentional non-local / deferred / re-verify
# constraint (kernel / rollup / discovery / ZKPassport ASN.1 length hints).
# Suppress HIGH only when this text is adjacent — failure mode is "miss a FP",
# never "hide a missing local assert without documentation".
_DEFERRED_CONSTRAINT_SAFETY_RE = re.compile(
    r"(?is)"
    r"(?:"
    r"kernel\s+(?:will\s+|circuits?\s+)?(?:validate|ensure|constrain)"
    r"|private\s+kernel"
    r"|validated\s+by\s+the\s+kernel"
    r"|constrained\s+(?:by|in)\s+the\s+(?:base\s+)?rollup"
    r"|constrained\s+against"
    r"|are\s+constrained\s+to"
    r"|AVM\s+(?:opcodes?\s+)?(?:are\s+)?constrained"
    r"|only\s+yields\s+an\s+undiscoverable"
    r"|untrusted"
    r"|hint\s+to\s+check"
    r"|read\s+request\s+validation"
    r"|before\s+a\s+constrained\s+tag"
    r"|malicious\s+oracle"
    r"|honest\s+oracle"
    r"|fail\s+to\s+produce\s+a\s+proof"
    r"|inclusion\s+proof"
    # ZKPassport / passport-circuit ASN.1 length + subarray-search hints:
    r"|as\s+checked\s+below"
    r"|checked\s+below"
    r"|checked\s+in\s+the\s+\w[\w\s]*circuit"
    r"|must\s+be\s+correct\s+for"
    r"|fully\s+re-?verified"
    r"|re-?verified\s+below"
    r"|only\s+used\s+as\s+a\s+starting\s+point"
    r"|verify\s+the\s+substring"
    r"|bound\s+to\s+the\s+nonce"
    r"|verifies\s+that\s+this\s+hash"
    r"|to\s+use\s+for\s+hashing"
    r")"
)


def _idents_bound_by_constraint_helper_calls(
    body: str,
    local_fn_names: Optional[Set[str]] = None,
    helper_summaries: Optional[dict] = None,
) -> Set[str]:
    """Identifiers passed into cross-module ``check_*`` / ``verify_*`` / … calls.

    Same-file helpers that appear in ``local_fn_names`` but NOT in
    ``helper_summaries`` are skipped (hollow return-only ``confirm_*``).
    """
    locals_ = local_fn_names or set()
    summaries = helper_summaries or {}
    bound: Set[str] = set()
    for cm in _CONSTRAINT_HELPER_NAME_RE.finditer(body):
        call = cm.group(0)
        name_m = re.match(r"(\w+)\s*\(", call)
        call_name = name_m.group(1) if name_m else ""
        if call_name in locals_ and call_name not in summaries:
            continue
        args = _split_top_level(_paren_segment(body, cm.end() - 1), ",")
        for arg in args:
            bound |= _idents(arg)
    return bound


def _is_intentional_unconstrained_entropy(unsafe_body: str) -> bool:
    """True when the ``unsafe`` block is solely ``random()`` — intentional
    privacy entropy that must NOT be re-constrained (aztec-nr note/ephemeral
    key archetypes). Only sound when paired with an adjacent Safety note."""
    return bool(re.fullmatch(r"\s*random\s*\(\s*\)\s*", unsafe_body or ""))


def _is_avm_opcode_hint(unsafe_body: str) -> bool:
    """True when the ``unsafe`` block is an AVM opcode call (``avm::...``).
    Aztec documents these as constrained by the AVM itself — only suppress with
    an adjacent Safety note."""
    return bool(re.match(r"\s*avm\s*::\s*\w+\s*\(", unsafe_body or ""))


def _is_documented_deferred_constraint(safety_text: Optional[str]) -> bool:
    """True when the Safety note documents kernel/rollup/discovery deferred binding."""
    if not safety_text:
        return False
    return bool(_DEFERRED_CONSTRAINT_SAFETY_RE.search(safety_text))


# ---------------------------------------------------------------------------
# Lexer
# ---------------------------------------------------------------------------

class NoirLexer:
    """Lexical soundness analyzer for Noir circuit source.

    ``include_tests=True`` disables test-context suppression (test filenames,
    ``#[test]`` functions, and ``mod test``/``mod tests`` blocks).
    """

    def __init__(self, include_tests: bool = False) -> None:
        self.include_tests = include_tests

    def analyze(self, content: str, file_path: Optional[Path] = None) -> List[Vulnerability]:
        if os.environ.get("AUDIT_NOIR_LEXER", "1") == "0":
            return []
        if not is_noir_source(content, str(file_path or "")):
            return []
        if not self.include_tests and _is_test_path(str(file_path or "")):
            return []

        stripped = _strip_comments(content)
        helper_summaries = _helper_constraint_summaries(stripped)
        local_fn_names = {name for name, _b, _o in _functions(stripped)}
        vulns: List[Vulnerability] = []
        for name, body, offset in _functions(stripped):
            vulns += self._detect_unconstrained_unsafe(
                content, body, offset, name, helper_summaries, local_fn_names,
            )
        vulns += self._detect_unconstrained_input(content, stripped)
        vulns += self._detect_unchecked_cast(content, stripped)
        for name, body, offset in _functions(stripped):
            vulns += self._detect_unasserted_bool(content, body, offset, name)
            vulns += self._detect_unused_check_result(content, body, offset, name)
            vulns += self._detect_vacuous_constraint(content, body, offset, name)
            vulns += self._detect_conditional_constrain(
                content, body, offset, name, stripped,
            )
        vulns += self._detect_conditional_assert(content, stripped)
        vulns += self._detect_unsafe_missing_safety(content, stripped)
        # Constraint-absence rules cannot apply inside `unconstrained fn`
        # bodies — there is no circuit there to under-constrain.
        unc = _unconstrained_line_ranges(content, stripped)
        if unc:
            vulns = [
                v for v in vulns
                if v.rule_id not in _UNCONSTRAINED_SUPPRESSED_RULES
                or not _in_ranges(v.location[0] if v.location else 0, unc)
            ]
        if not self.include_tests:
            ranges = _test_line_ranges(content, stripped)
            if ranges:
                vulns = [
                    v for v in vulns
                    if not _in_ranges(v.location[0] if v.location else 0, ranges)
                ]
        return _apply_suppressions(content, vulns)

    # --- Rule 1: unconstrained `unsafe {}` result -------------------------

    def _detect_unconstrained_unsafe(
        self,
        src: str,
        body: str,
        body_offset: int,
        fn_name: str,
        helper_summaries: Optional[dict] = None,
        local_fn_names: Optional[Set[str]] = None,
    ) -> List[Vulnerability]:
        # Identifiers that ARE bound by a constraint in this function body:
        # seed from the assert family (arguments plus method-call receivers),
        # then walk backward through `let name = rhs;` bindings until the
        # constrained set reaches a fixpoint. This mirrors
        # `_reachable_to_constraint_or_output` so an unsafe hint re-derived
        # through multiple locals is treated as bound.
        constrained: Set[str] = _seed_from_asserts(body)

        # Same-file helpers: args passed into parameters the helper *asserts*
        # count as constrained — aztec-nr `confirm_hinted_note`, etc.
        summaries = helper_summaries or {}
        locals_ = local_fn_names or set()
        for helper_name, reachable_positions in summaries.items():
            if helper_name == fn_name:
                continue
            for cm in re.finditer(r"\b" + re.escape(helper_name) + r"\s*\(", body):
                if cm.start() > 0 and body[cm.start() - 1] == ".":
                    continue
                args = _split_top_level(_paren_segment(body, cm.end() - 1), ",")
                for idx in reachable_positions:
                    if idx >= len(args):
                        continue
                    constrained |= _idents(args[idx])

        # Cross-module convention: `constrain_*` / `confirm_*` / `verify_*` /
        # `check_*` call sites. Skip names defined in THIS file that are not
        # assert-crediting (hollow confirm that only returns the hint — miss-not-hide).
        constrained |= _idents_bound_by_constraint_helper_calls(body, locals_, summaries)

        _expand_constrained_through_lets(constrained, body)

        out: List[Vulnerability] = []
        for um in re.finditer(r"\blet\s+(?:mut\s+)?([\w(),\s]{0,200}?)\s*=\s*unsafe\s*\{", body):
            # binding names, dropping `mut` and `_`-prefixed (intentionally unused)
            names = [w for w in re.findall(r"\w+", um.group(1))
                     if w != "mut" and not w.startswith("_")]
            free = [w for w in names if w not in constrained]
            if not free:
                continue

            # Intentional trust boundaries (only with adjacent `// Safety:`):
            # - `unsafe { random() }` — privacy entropy the sender already knows
            # - `unsafe { avm::opcode(...) }` — constrained by the AVM itself
            # - Safety documents kernel/rollup/discovery deferred constraint
            unsafe_body = _brace_segment(body, um.end() - 1)
            unsafe_kw = body.find("unsafe", um.start(), um.end())
            safety_off = body_offset + (unsafe_kw if unsafe_kw >= 0 else um.start())
            safety_text = _adjacent_safety_comment_text(src, safety_off)
            if safety_text and (
                _is_intentional_unconstrained_entropy(unsafe_body)
                or _is_avm_opcode_hint(unsafe_body)
                or _is_documented_deferred_constraint(safety_text)
            ):
                continue

            # Dead hint: bound from unsafe then never referenced. Not a soundness
            # hole (nothing reads the free value); skip rather than HIGH (ZKPassport
            # facematch codegen sometimes leaves unused ASN.1 length locals).
            stmt_end = um.end() - 1 + len(unsafe_body) + 2  # past closing `}`
            while stmt_end < len(body) and body[stmt_end] in " \t\r\n":
                stmt_end += 1
            if stmt_end < len(body) and body[stmt_end] == ";":
                stmt_end += 1
            rest = body[stmt_end:]
            free = [w for w in free if re.search(r"\b" + re.escape(w) + r"\b", rest)]
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

        # Shallow lexical interprocedural summary: if ``main`` passes a simple
        # identifier to a helper parameter that the helper constrains or returns,
        # treat that main identifier as reachable too. This is intentionally
        # bounded (one call edge, direct calls, positional args only) to keep the
        # scanner dependency-free and predictable.
        for helper_name, reachable_positions in _helper_constraint_summaries(stripped).items():
            if helper_name == "main":
                continue
            for cm in re.finditer(r"\b" + re.escape(helper_name) + r"\s*\(", body):
                # Keep this to free-function calls, not method-style ``x.helper(...)``.
                if cm.start() > 0 and body[cm.start() - 1] == ".":
                    continue
                args = _split_top_level(_paren_segment(body, cm.end() - 1), ",")
                for idx in reachable_positions:
                    if idx >= len(args):
                        continue
                    arg = args[idx].strip()
                    if re.fullmatch(r"[A-Za-z_]\w*", arg):
                        reachable.add(arg)

        # Cross-module ``check_*`` / ``verify_*`` / … (ZKPassport integrity, ECDSA
        # verify helpers, …). Method-style ``trees.check_*(...)`` is included —
        # the helper name regex matches the basename after ``.``.
        local_fn_names = {name for name, _b, _o in _functions(stripped)}
        summaries = _helper_constraint_summaries(stripped)
        reachable |= _idents_bound_by_constraint_helper_calls(
            body, local_fn_names, summaries,
        )
        _expand_constrained_through_lets(reachable, body)

        out: List[Vulnerability] = []
        sig = re.search(r"\bfn\s+main\s*\(", stripped)
        line = _line_of(src, sig.start()) if sig else 0
        for name, is_pub in params:
            # `_`-prefixed params are conventionally intentionally-unused.
            if name.startswith("_") or name in reachable:
                continue
            if is_pub:
                # A public input that reaches no constraint is the DUAL of the
                # private case: the verifier is handed a value the circuit never
                # uses, so the proof asserts nothing about it. A circuit taking
                # `merkle_root: pub Field` and never touching it lets a verifier
                # believe membership was proven against that root when it was
                # not. MEDIUM rather than HIGH — an unused public input is also
                # a legitimate idiom for binding a proof to a context (nonce,
                # chain id, recipient), which is indistinguishable lexically.
                out.append(Vulnerability(
                    pattern_name="NOIR_UNCONSTRAINED_PUBLIC_INPUT",
                    severity=Severity.MEDIUM,
                    function="main",
                    location=(line, 0),
                    origin_tier=NOIR_ORIGIN_TIER,
                    rule_id="NOIR_UNCONSTRAINED_PUBLIC_INPUT",
                    title=f"Public input `{name}` is never used in `main`",
                    description=(
                        f"`{name}` is a PUBLIC input of the circuit `main`, but it reaches "
                        f"no constraint and no output — the circuit never reads it. A "
                        f"verifier checking the proof against `{name}` therefore learns "
                        f"nothing about it: the statement appears to be about `{name}` "
                        f"while the circuit ignores it. If `{name}` is meant to pin down "
                        f"the computation (a Merkle root, a commitment, an expected hash), "
                        f"constrain it — e.g. `assert(computed == {name})`. If it exists "
                        f"only to bind the proof to a context (nonce / chain id / "
                        f"recipient), that is a legitimate idiom and this finding is a "
                        f"false positive: suppress it with "
                        f"`// o1js-scan-disable-line NOIR_UNCONSTRAINED_PUBLIC_INPUT`."
                    ),
                    evidence={
                        "witness": name, "function": "main",
                        "witness_source": "public_input", "framework": "noir",
                    },
                ))
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
        assertion (`assert(ident < N)`), an explicit bit-size assertion, or a
        found-sentinel (`assert(ident != -1)`) used by passport country-list
        index hints before ``as u32`` indexing."""
        a = re.escape(ident)
        if re.search(r"\b" + a + r"\s*\.\s*assert(?:_max)?_bit_size\b", text):
            return True
        for am in _ASSERT_CALL_RE.finditer(text):
            seg = _paren_segment(text, am.end() - 1)
            if re.search(r"\b" + a + r"\b", seg) and re.search(r"[<>]=?", seg):
                return True
            # ZKPassport ``unsafe_get_index`` archetype: assert found, then index.
            if re.search(r"\b" + a + r"\s*!=\s*-?\s*1\b", seg):
                return True
        return False

    def _detect_unchecked_cast(self, src: str, stripped: str) -> List[Vulnerability]:
        # Prover-controlled value sources this tool already models: private
        # `main` inputs and `unsafe {}` results. Scoping the rule to these keeps
        # it high-signal (loop counters / known-small locals are not flagged).
        controlled = _controlled_witnesses(stripped)
        if not controlled:
            return []

        # Propagate controlled-ness forward through simple `let name = rhs;`
        # aliases/derived values before looking for casts. This intentionally
        # mirrors the lexical let-binding shape used by the reachability rules
        # above and expands to a fixpoint so multi-hop derivations are covered.
        lets = [(m.group(1), m.group(2)) for m in re.finditer(
            r"\blet\s+(?:mut\s+)?(\w+)\s*=\s*([^;]{0,4000});", stripped)]
        changed = True
        while changed:
            changed = False
            for name, rhs in lets:
                if name in controlled or name.startswith("_"):
                    continue
                if any(idt in controlled for idt in _idents(rhs)):
                    controlled.add(name)
                    changed = True

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

    # --- Rule 5b: unused check / confirm / verify result ------------------

    def _detect_unused_check_result(
        self, src: str, body: str, body_offset: int, fn_name: str,
    ) -> List[Vulnerability]:
        """Flag check/confirm/verify/constrain calls whose result is discarded.

        Closes the FN hole where call-site name credit binds ``unsafe`` args
        even when the check's return value is never asserted.
        """
        asserted: Set[str] = _seed_from_asserts(body)
        _expand_constrained_through_lets(asserted, body)

        out: List[Vulnerability] = []

        # (a) bare discarded membership-check call as a terminated statement.
        # verify_/confirm_/constrain_ bare calls are allowed (side-effect assert).
        for stmt, off, terminated in _top_level_statements(body):
            if not terminated:
                continue
            s = stmt.strip()
            m = _BARE_UNUSED_CHECK_RE.match(s)
            if not m:
                continue
            depth = 0
            i = m.end() - 1
            while i < len(s):
                if s[i] == "(":
                    depth += 1
                elif s[i] == ")":
                    depth -= 1
                    if depth == 0:
                        i += 1
                        break
                i += 1
            if s[i:].strip():
                continue
            line = _line_of(src, body_offset + off + (stmt.find(m.group(0))))
            out.append(Vulnerability(
                pattern_name="NOIR_UNUSED_CHECK_RESULT",
                severity=Severity.HIGH,
                function=fn_name,
                location=(line, 0),
                origin_tier=NOIR_ORIGIN_TIER,
                rule_id="NOIR_UNUSED_CHECK_RESULT",
                title=f"Unused check/confirm result in `{fn_name}`",
                description=(
                    f"A `{m.group(0).rstrip('(')}` call's result is discarded. Calling a "
                    f"membership check does not constrain the circuit unless its return "
                    f"value is asserted (or used to gate an effect). Bind the result with "
                    f"`assert(...)` — analog of unused verification."
                ),
                evidence={"function": fn_name, "call": m.group(0).rstrip("("),
                          "framework": "noir"},
            ))

        # (b) let-bound check result never asserted
        for names, rhs in _let_bindings(body):
            cm = _CHECK_RESULT_NAME_RE.search(rhs)
            if not cm:
                continue
            if any(n in asserted for n in names):
                continue
            line_off = body.find(f"let {names[0]}") if names else 0
            if line_off < 0:
                line_off = 0
            line = _line_of(src, body_offset + max(line_off, 0))
            out.append(Vulnerability(
                pattern_name="NOIR_UNUSED_CHECK_RESULT",
                severity=Severity.MEDIUM,
                function=fn_name,
                location=(line, 0),
                origin_tier=NOIR_ORIGIN_TIER,
                rule_id="NOIR_UNUSED_CHECK_RESULT",
                title=f"Check result `{names[0]}` never asserted in `{fn_name}`",
                description=(
                    f"`{names[0]}` holds the result of a check/confirm/verify call but is "
                    f"never asserted. The check's return value must gate the circuit "
                    f"(e.g. `assert({names[0]})`); otherwise the prover can ignore it."
                ),
                evidence={"witness": names[0], "function": fn_name, "framework": "noir"},
            ))
        return out

    # --- Rule 5c: constrain/confirm gated by prover-controlled condition --

    def _detect_conditional_constrain(
        self, src: str, body: str, body_offset: int, fn_name: str, stripped: str,
    ) -> List[Vulnerability]:
        """``constrain_*`` / ``confirm_*`` / ``verify_*`` only under a
        prover-controlled ``if``, while an ``unsafe`` hint still reaches output.
        """
        if fn_name == "main":
            controlled = {
                n for n, is_pub in _main_params(stripped)
                if not is_pub and not n.startswith("_")
            }
        else:
            controlled = {
                n for n in _function_params(stripped, fn_name)
                if not n.startswith("_")
            }
        for um in re.finditer(r"\blet\s+(?:mut\s+)?([\w(),\s]{0,200}?)\s*=\s*unsafe\s*\{", body):
            controlled |= {w for w in re.findall(r"\w+", um.group(1))
                           if w != "mut" and not w.startswith("_")}
        if not controlled:
            return []

        unsafe_names = {
            w for um in re.finditer(
                r"\blet\s+(?:mut\s+)?([\w(),\s]{0,200}?)\s*=\s*unsafe\s*\{", body)
            for w in re.findall(r"\w+", um.group(1))
            if w != "mut" and not w.startswith("_")
        }
        output_idents = _idents(_trailing_expr(body))
        for rm in re.finditer(r"\breturn\b([^;]{0,4000});", body):
            output_idents |= _idents(rm.group(1))
        if not (unsafe_names & output_idents):
            return []

        out: List[Vulnerability] = []
        n = len(body)
        for im in re.finditer(r"\bif\b", body):
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
            core = cond[1:].strip() if cond.startswith("!") else cond
            if not re.fullmatch(r"\w+", core) or core not in controlled:
                continue
            depth = 0
            k = j
            while k < n:
                c = body[k]
                if c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        break
                k += 1
            block = body[j + 1:k]
            if not _CONSTRAINT_HELPER_NAME_RE.search(block):
                continue
            line = _line_of(src, body_offset + im.start())
            out.append(Vulnerability(
                pattern_name="NOIR_CONDITIONAL_CONSTRAIN",
                severity=Severity.MEDIUM,
                function=fn_name,
                location=(line, 0),
                origin_tier=NOIR_ORIGIN_TIER,
                rule_id="NOIR_CONDITIONAL_CONSTRAIN",
                title=f"Constrain/confirm gated by prover-controlled `{core}` in `{fn_name}`",
                description=(
                    f"A `constrain_*` / `confirm_*` / `verify_*` call runs inside "
                    f"`if {cond} {{ ... }}`, and `{core}` is prover-controlled, while an "
                    f"`unsafe` hint still reaches the function output. The prover can set "
                    f"`{core}` false to skip the constrain and leave the hint free. Enforce "
                    f"the constrain unconditionally, or constrain `{core}` itself."
                ),
                evidence={"condition": core, "function": fn_name, "framework": "noir"},
            ))
        return out

    # --- Rule 6: vacuous (trivially-true) constraint ----------------------

    def _detect_vacuous_constraint(
        self, src: str, body: str, body_offset: int, fn_name: str,
    ) -> List[Vulnerability]:
        """Flag constraints that are satisfied by construction.

        A vacuous constraint is worse than a missing one: the code *looks*
        checked, so review stops there, while the circuit binds nothing.
        `assert(expected == expected)` is a one-character slip from
        `assert(computed == expected)`.
        """
        out: List[Vulnerability] = []
        for am in _ASSERT_CALL_RE.finditer(body):
            call = body[am.start():am.end() - 1]
            name = re.sub(r"::<.*", "", call).strip()
            args = _split_top_level(_paren_segment(body, am.end() - 1), ",")
            if not args:
                continue

            reason: Optional[Tuple[str, bool]] = None
            # `assert_eq(a, a)` — two-operand form.
            if "eq" in name and len(args) >= 2:
                lhs, rhs = _norm_expr(args[0]), _norm_expr(args[1])
                if lhs and lhs == rhs:
                    reason = (f"both operands of `{name}` are `{lhs}`", True)
            # `<receiver>.assert_eq(receiver)` — method form.
            if reason is None and "eq" in name:
                j = am.start() - 1
                while j >= 0 and body[j].isspace():
                    j -= 1
                if j >= 0 and body[j] == ".":
                    recv = _norm_expr(body[_expr_start(body, j):j])
                    if recv and recv == _norm_expr(args[0]):
                        reason = (f"`{name}` compares `{recv}` with itself", True)
            # `assert(cond)` — condition form (message arg, if any, ignored).
            if reason is None:
                reason = _vacuous_reason(args[0])
            if reason is None:
                continue

            text, is_typo = reason
            line = _line_of(src, body_offset + am.start())
            out.append(Vulnerability(
                pattern_name="NOIR_VACUOUS_CONSTRAINT",
                severity=Severity.HIGH if is_typo else Severity.MEDIUM,
                function=fn_name,
                location=(line, 0),
                origin_tier=NOIR_ORIGIN_TIER,
                rule_id="NOIR_VACUOUS_CONSTRAINT",
                title=f"Constraint is always satisfied in `{fn_name}`",
                description=(
                    f"This constraint is trivially true — {text} — so it adds no "
                    f"restriction to the circuit. A vacuous constraint is more dangerous "
                    f"than a missing one: the code reads as checked, so review stops "
                    f"there, while the prover remains free. "
                    + (
                        "A self-comparison is almost always a typo for a real check "
                        "(`assert(computed == expected)` mistyped as "
                        "`assert(expected == expected)`) — compare against the value it "
                        "was meant to be checked against."
                        if is_typo else
                        "If this is a placeholder, replace it with the real constraint or "
                        "remove it; a constant condition proves nothing."
                    )
                ),
                evidence={
                    "function": fn_name, "expr": args[0].strip()[:80],
                    "framework": "noir",
                },
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
            if not _ASSERT_CALL_RE.search(block):
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
            # adjacent to the block or the enclosing statement. Check only the
            # same line and the immediately preceding comment region in the RAW
            # source (comments are stripped in `stripped`).
            if _has_adjacent_safety_comment(src, um.start()):
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


def analyze_noir_file(
    filepath: str, source: str, include_tests: bool = False,
) -> List[Vulnerability]:
    """Analyze a single Noir file's ``source`` text.

    ``include_tests=True`` reports findings from test code too (suppressed by
    default; see ``_is_test_path`` / ``_test_line_ranges``).
    """
    return NoirLexer(include_tests=include_tests).analyze(source, Path(filepath))
