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

from .lexer import _apply_suppressions, _line_of, _paren_segment, _strip_comments
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
        vulns += self._detect_unsafe_missing_safety(content, stripped)
        return _apply_suppressions(content, vulns)

    # --- Rule 1: unconstrained `unsafe {}` result -------------------------

    def _detect_unconstrained_unsafe(
        self, src: str, body: str, body_offset: int, fn_name: str,
    ) -> List[Vulnerability]:
        # Identifiers that ARE bound by a constraint in this function body:
        # everything mentioned inside an assert/assert_eq, plus one `let` hop
        # (a value asserted through an intermediate local — e.g. a `remainder`
        # computed from the hint and then asserted).
        asserted: Set[str] = set()
        for am in re.finditer(r"\bassert(?:_eq)?\s*\(", body):
            asserted |= _idents(_paren_segment(body, am.end() - 1))
        hop: Set[str] = set()
        for lm in re.finditer(r"\blet\s+(?:mut\s+)?(\w+)\s*=\s*([^;]{0,4000});", body):
            if lm.group(1) in asserted:
                hop |= _idents(lm.group(2))
        constrained = asserted | hop

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

    # --- Rule 2: `unsafe {}` without a `// Safety:` note ------------------

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
