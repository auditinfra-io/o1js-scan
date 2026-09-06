"""Semantics-preserving reformatting must not change what the analyzer reports.

WHY THIS EXISTS
---------------
The frontend is lexical — regex and brace matching over source text — so its
behaviour depends on formatting in a way a real parser's would not. Nothing
measured that dependence. A contributor tightening a regex could have made the
analyzer blind to Prettier-wrapped calls without a single test noticing.

Each mutation below rewrites a corpus fixture in a way that changes no
semantics, then asserts the reported ``(rule_id, severity, function)`` set is
unchanged. Line numbers are deliberately excluded — they are expected to move.

Mutations are split in two:

* ``ENFORCED`` — the analyzer survives these today, and must keep doing so.
* ``KNOWN_FRAGILE`` — these change the verdict on the fixtures listed in
  ``KNOWN_GAPS``. Rather than deleting the mutation and pretending the gap does
  not exist, the exact set is committed. A *new* gap fails the test, and so does
  a gap that gets *fixed* — which forces the manifest to be updated instead of
  quietly drifting.

Everything here is deterministic; no fixture is randomly generated.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from o1js_scan import analyze_file, analyze_noir_file

CORPUS = Path(__file__).resolve().parent / "corpus"


# ───────────────────────────────────────────────────────────────────
# Mutations
# ───────────────────────────────────────────────────────────────────

def _code_lines_only(transform):
    """Apply ``transform`` to code only, never to comments or string literals.

    Learned the hard way: an early version rewrote text inside a `//` comment
    and split it across lines, so the tail stopped being a comment and the
    fixture stopped being valid TypeScript. The analyzer then "lost" findings,
    and that would have been recorded as fragility it does not have. A mutation
    that changes semantics measures nothing.
    """

    def mutate(src: str) -> str:
        out, in_block = [], False
        for line in src.splitlines():
            stripped = line.strip()
            if in_block:
                out.append(line)
                if "*/" in line:
                    in_block = False
                continue
            if stripped.startswith("/*"):
                out.append(line)
                in_block = "*/" not in line
                continue
            # Leave whole-line comments, and any line carrying a string
            # literal or trailing comment, exactly as they are.
            if stripped.startswith("//") or "//" in line or '"' in line or "'" in line:
                out.append(line)
                continue
            out.append(transform(line))
        return "\n".join(out)

    return mutate


def blank_lines(src: str) -> str:
    """Double-space every line."""
    return src.replace("\n", "\n\n")


def indent(src: str) -> str:
    """Indent the whole file, as wrapping it in a namespace would."""
    return "\n".join(("    " + ln) if ln.strip() else ln for ln in src.splitlines())


def line_comments(src: str) -> str:
    """Append a trailing comment to every code line."""
    return "\n".join(
        ln + ("  // metamorphic note" if ln.strip() and not ln.strip().startswith("//") else "")
        for ln in src.splitlines()
    )


def crlf(src: str) -> str:
    """Windows line endings."""
    return src.replace("\n", "\r\n")


def trailing_whitespace(src: str) -> str:
    return "\n".join(ln + "   " for ln in src.splitlines())


multiline_args = _code_lines_only(
    lambda ln: re.sub(r"\(\s*([^()\n]{1,60}?)\s*\)", r"(\n      \1\n    )", ln)
)
multiline_args.__name__ = "multiline_args"

spaced_dots = _code_lines_only(
    lambda ln: re.sub(r"(?<![./*])\.(?![.0-9/])", " . ", ln)
)
spaced_dots.__name__ = "spaced_dots"

spaced_parens = _code_lines_only(
    lambda ln: re.sub(r"\(", " ( ", ln).replace(")", " ) ")
)
spaced_parens.__name__ = "spaced_parens"


ENFORCED = (blank_lines, indent, line_comments, crlf, trailing_whitespace)
KNOWN_FRAGILE = (multiline_args, spaced_dots, spaced_parens)

# (language, fixture, mutation) pairs whose verdict currently changes.
# Measured, not aspirational: see the module docstring for why they are listed
# rather than removed. All four are exotic spacing (`a . b`, `f ( x )`) that no
# formatter emits, so the practical exposure is low — but they are real, and
# `multiline_args`, the one that would have mattered, is NOT here: the analyzer
# handles Prettier-style wrapping correctly, including wrapped method
# signatures. An earlier version of this file claimed otherwise because the
# mutation itself was broken.
KNOWN_GAPS = frozenset({
    ("o1js", "fp_semantic_alias_helper_chain.ts", "spaced_parens"),
    ("o1js", "tp_regression_mac_unasserted_bool.ts", "spaced_dots"),
    ("o1js", "tp_semantic_multicontract_scope.ts", "spaced_parens"),
    ("o1js", "tp_state_read_after_write.ts", "spaced_parens"),
})


# ───────────────────────────────────────────────────────────────────
# Harness
# ───────────────────────────────────────────────────────────────────

def _classification(analyze, name: str, src: str) -> set:
    """What the analyzer says, minus line numbers."""
    return {
        (v.rule_id, str(getattr(v.severity, "value", v.severity)), v.function)
        for v in analyze(name, src)
    }


def _cases():
    """(language, path, scan_as, analyze) for every fixture with findings."""
    for lang, pattern, analyze in (
        ("o1js", "o1js/*.ts", analyze_file),
        ("noir", "noir/*.nr", analyze_noir_file),
    ):
        for path in sorted(CORPUS.glob(pattern)):
            src = path.read_text(encoding="utf-8")
            match = re.search(r"@scan-as\s+(\S+)", src)
            # The corpus lives under tests/, which the path classifier skips as
            # test code; o1js fixtures must declare @scan-as, Noir ones may fall
            # back to the bare filename exactly as their own corpus test does.
            if match:
                scan_as = match.group(1)
            elif lang == "noir":
                scan_as = path.name
            else:
                continue
            if not _classification(analyze, scan_as, src):
                continue  # nothing to preserve
            yield lang, path, scan_as, analyze


CASES = list(_cases())
MUTATION_CASES = [
    (lang, path, scan_as, analyze, mut)
    for lang, path, scan_as, analyze in CASES
    for mut in ENFORCED + KNOWN_FRAGILE
]


def test_the_corpus_actually_produces_findings_to_preserve():
    """A vacuous sweep over empty classifications would pass trivially."""
    assert len(CASES) >= 15, f"only {len(CASES)} fixtures have findings"


@pytest.mark.parametrize(
    "lang,path,scan_as,analyze,mutation",
    MUTATION_CASES,
    ids=[f"{lang}-{p.name}-{m.__name__}" for lang, p, _, _, m in MUTATION_CASES],
)
def test_reformatting_preserves_the_verdict(lang, path, scan_as, analyze, mutation):
    src = path.read_text(encoding="utf-8")
    before = _classification(analyze, scan_as, src)
    after = _classification(analyze, scan_as, mutation(src))
    known = (lang, path.name, mutation.__name__) in KNOWN_GAPS

    if known:
        assert before != after, (
            f"{path.name} now survives {mutation.__name__}. Remove it from "
            f"KNOWN_GAPS — the manifest records measured fragility, so a fix "
            f"must update it."
        )
        return

    lost = sorted(before - after)
    gained = sorted(after - before)
    assert not lost and not gained, (
        f"{mutation.__name__} changed the verdict on {path.name} without "
        f"changing semantics.\n  lost:   {lost}\n  gained: {gained}\n"
        f"Either the frontend regressed, or this is newly measured fragility "
        f"that belongs in KNOWN_GAPS with a note."
    )


def test_known_gaps_all_refer_to_real_fixtures():
    """A stale manifest entry would silently exempt nothing."""
    live = {(lang, path.name) for lang, path, _, _ in CASES}
    mutations = {m.__name__ for m in ENFORCED + KNOWN_FRAGILE}
    for lang, name, mutation in KNOWN_GAPS:
        assert (lang, name) in live, f"KNOWN_GAPS names a missing fixture: {name}"
        assert mutation in mutations, f"KNOWN_GAPS names an unknown mutation: {mutation}"
