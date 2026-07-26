"""Command-line entry point for o1js-scan / noir-scan.

    o1js-scan <path> [--lang LANG] [--json | --sarif [FILE]] [--fail-on LEVEL]
    noir-scan <path> ...   # same binary (Noir-friendly alias)

Exits 1 when a finding at or above the ``--fail-on`` level (default ``high``)
is present, 0 otherwise, and 2 when the scan path does not exist.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path
from typing import List, Optional

from . import __version__
from .lexer import analyze_project
from .paths import ScanStats
from .vuln import meets_threshold

_FAIL_ON_CHOICES = ("critical", "high", "medium", "low", "none")
_LANG_CHOICES = ("auto", "o1js", "noir")


def _prog_name(argv: Optional[List[str]]) -> str:
    """Prefer the invoked binary name so ``noir-scan --help`` reads as Noir."""
    env_prog = os.environ.get("O1JS_SCAN_PROG")
    if env_prog in {"o1js-scan", "noir-scan"}:
        return env_prog
    if argv is not None:
        return "o1js-scan"
    name = Path(sys.argv[0]).name
    if name.endswith("noir-scan") or name == "noir-scan":
        return "noir-scan"
    return "o1js-scan"


def main(argv: Optional[List[str]] = None) -> int:
    prog = _prog_name(argv)
    ap = argparse.ArgumentParser(
        prog=prog,
        description=(
            "Static soundness scanner for o1js / Mina zkApps and Noir circuits "
            "(under-constrained witnesses, unsafe hints, range casts)."
        ),
    )
    ap.add_argument("path", help="file or directory to scan")
    ap.add_argument("--version", action="version", version=f"{prog} {__version__}")
    ap.add_argument(
        "--lang", choices=_LANG_CHOICES, default="auto", metavar="LANG",
        help="which sources to analyze "
             f"({'|'.join(_LANG_CHOICES)}; default: auto = both).",
    )
    ap.add_argument(
        "--include-tests", action="store_true",
        help="also report findings in test code (BOTH backends): *.test.ts / "
             "*.spec.ts / .js variants, test_*.nr / *_test.nr, any test/, "
             "tests/ or __tests__/ directory, plus Noir #[test] functions and "
             "mod test blocks. Excluded by default: tests deliberately build "
             "invalid values to prove the asserts reject them.",
    )
    ap.add_argument(
        "--include-examples", action="store_true",
        help="keep the original severity for findings in example code (an "
             "examples/ or example/ directory, or an .eg. filename). By default "
             "these are downgraded to LOW — still reported, but they will not "
             "fail a build — because example code is deliberately simplified.",
    )
    ap.add_argument("--json", action="store_true", help="emit JSONL findings")
    ap.add_argument(
        "--sarif", nargs="?", const="o1js-scan.sarif", default=None, metavar="FILE",
        help="write SARIF 2.1.0 to FILE (default o1js-scan.sarif; '-' for stdout) "
             "for GitHub code scanning",
    )
    ap.add_argument(
        "--fail-on", choices=_FAIL_ON_CHOICES, default="high", metavar="LEVEL",
        help="minimum severity that makes the run exit 1 "
             f"({'|'.join(_FAIL_ON_CHOICES)}; default: high). 'none' never fails.",
    )
    args = ap.parse_args(argv)

    # Fail loudly on a missing path. Otherwise a typo'd scan target silently
    # produces zero findings and exit 0 — a green CI run that scanned nothing.
    if not Path(args.path).exists():
        print(f"{prog}: path not found: {args.path}", file=sys.stderr)
        return 2

    stats = ScanStats()
    findings = analyze_project(
        args.path, lang=args.lang, include_tests=args.include_tests,
        include_examples=args.include_examples, stats=stats,
    )

    gate = any(meets_threshold(v.severity.value, args.fail_on) for _f, v in findings)

    # SARIF is written even when the exit gate trips below, so the CI upload
    # step still runs on a repo that has high findings.
    if args.sarif is not None:
        from .sarif import to_sarif

        doc = json.dumps(to_sarif(findings, __version__, stats=stats), indent=2)
        if args.sarif == "-":
            # SARIF owns stdout in this mode; skip the other reporters so the
            # document parses cleanly when piped to the upload action.
            print(doc)
            return 1 if gate else 0
        Path(args.sarif).write_text(doc, encoding="utf-8")
        print(f"{prog}: wrote SARIF to {args.sarif}", file=sys.stderr)

    if args.json:
        for fp, v in findings:
            print(json.dumps({
                "file": fp,
                "rule_id": v.rule_id,
                "severity": v.severity.value.lower(),
                "function": v.function,
                "line": (v.location or [0])[0],
                "title": v.title,
                "evidence": v.evidence,
            }))
    else:
        for fp, v in findings:
            line = (v.location or [0])[0]
            print(f"{v.severity.value.upper():<8} {v.rule_id:<34} "
                  f"{Path(fp).name}:{line}  fn={v.function}  {v.title}")

    print(_summary(prog, findings, args.fail_on, gate, args.lang), file=sys.stderr)
    # Silent suppression is invisible: say what was skipped or downgraded, on
    # stderr so --json / --sarif consumers are unaffected.
    note = stats.note()
    if note:
        print(f"{prog}: {note}", file=sys.stderr)
    return 1 if gate else 0


def _summary(prog: str, findings, fail_on: str, gate: bool, lang: str) -> str:
    """One-line stderr summary: counts by severity and the gate outcome."""
    if not findings:
        if lang == "noir":
            return f"{prog}: no findings (or no Noir .nr files found)"
        if lang == "o1js":
            return f"{prog}: no findings (or no o1js files found)"
        return f"{prog}: no findings (or no Noir / o1js sources found)"
    counts = Counter(v.severity.value.lower() for _f, v in findings)
    by_sev = ", ".join(
        f"{counts[s]} {s}" for s in ("critical", "high", "medium", "low", "info")
        if counts[s]
    )
    files = len({fp for fp, _v in findings})
    verdict = (f"fails (--fail-on {fail_on})" if gate
               else f"passes (--fail-on {fail_on})")
    return (f"{prog}: {len(findings)} finding(s) [{by_sev}] "
            f"in {files} file(s) — {verdict}")


if __name__ == "__main__":
    sys.exit(main())
