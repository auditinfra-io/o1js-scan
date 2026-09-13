"""Command-line entry point for o1js-scan / noir-scan.

    o1js-scan <path> [--lang LANG] [--json | --sarif [FILE]] [--fail-on LEVEL]
    noir-scan <path> ...   # same binary (Noir-friendly alias)

Exits 1 when a finding at or above the ``--fail-on`` level (default ``high``)
is present, 0 otherwise, and 2 when the scan examined nothing — either the path
does not exist, or it holds no analyzable source. ``--allow-empty`` turns the
second case back into a 0 for a directory that legitimately has no circuits.
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
        "--explain", action="store_true",
        help="show semantic source-to-sink paths beneath text findings when available",
    )
    ap.add_argument(
        "--sarif", nargs="?", const="o1js-scan.sarif", default=None, metavar="FILE",
        help="write SARIF 2.1.0 to FILE (default o1js-scan.sarif; '-' for stdout) "
             "for GitHub code scanning",
    )
    gate_group = ap.add_mutually_exclusive_group()
    gate_group.add_argument(
        "--fail-on", choices=_FAIL_ON_CHOICES, default=None, metavar="LEVEL",
        help="minimum severity that makes the run exit 1 "
             f"({'|'.join(_FAIL_ON_CHOICES)}; default: high). 'none' never fails.",
    )
    gate_group.add_argument(
        "--strict", action="store_true",
        help="progressive/power-user gate: fail on MEDIUM or higher (shorthand "
             "for --fail-on medium; LOW findings remain visible but advisory).",
    )
    ap.add_argument(
        "--allow-empty", action="store_true",
        help="exit 0 when no analyzable sources are found instead of exiting 2. "
             "For a deliberate scan of a directory that may legitimately hold no "
             "circuits, such as one leg of a monorepo CI matrix.",
    )
    args = ap.parse_args(argv)
    fail_on = "medium" if args.strict else (args.fail_on or "high")

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

    # The same guarantee, one step further in. A path that EXISTS but holds
    # nothing analyzable produced "no findings" and exit 0 — indistinguishable
    # from a clean scan, and far likelier than a typo: a refactor that moves
    # src/, a --lang that does not match the project, a monorepo subdirectory.
    # A run that examined nothing is reported as a failure, never as a pass.
    if stats.analyzed_files == 0 and not args.allow_empty:
        detail = (
            f"{stats.matched_files} file(s) matched the scan globs but none was "
            f"{_lang_noun(args.lang)} source"
            if stats.matched_files
            else "no files matched the scan globs"
        )
        skipped = (
            f"\n{prog}: {stats.skipped_test_files} file(s) were skipped as test code; "
            f"--include-tests to scan them"
            if stats.skipped_test_files
            else ""
        )
        print(
            f"{prog}: nothing to scan under {args.path} — {detail}.\n"
            f"{prog}: a run that examined no files is reported as a failure, not a "
            f"clean pass. Check the path and --lang, or pass --allow-empty if this "
            f"is expected.{skipped}",
            file=sys.stderr,
        )
        return 2

    gate = any(meets_threshold(v.severity.value, fail_on) for _f, v in findings)

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
            if args.explain:
                path = (v.evidence or {}).get("semantic_path")
                if path:
                    print(f"  source: {path['source']}")
                    print("  flow:")
                    for step in path.get("flow", []):
                        print(f"    -> {step['label']} ({step['method']}:{step['line']})")
                    print(f"  sink: {path['sink']}")
                    print(f"  binding: {path['binding']}")

    print(_summary(prog, findings, fail_on, gate, args.lang, stats.analyzed_files),
          file=sys.stderr)
    # Silent suppression is invisible: say what was skipped or downgraded, on
    # stderr so --json / --sarif consumers are unaffected.
    note = stats.note()
    if note:
        print(f"{prog}: {note}", file=sys.stderr)
    return 1 if gate else 0


def _lang_noun(lang: str) -> str:
    return {"noir": "Noir", "o1js": "o1js"}.get(lang, "o1js or Noir")


def _summary(prog: str, findings, fail_on: str, gate: bool, lang: str,
             analyzed_files: int = 0) -> str:
    """One-line stderr summary: what was examined, counts, and the gate outcome.

    The no-findings line used to read "no findings (or no sources found)",
    which conflated a clean scan with a scan that looked at nothing and
    returned exit 0 either way. It now states how many files were analyzed, so
    the two are distinguishable at a glance; the zero case never reaches here,
    because the caller treats it as a failure.
    """
    if not findings:
        return (f"{prog}: no findings in "
                f"{analyzed_files} {_lang_noun(lang)} file(s) — "
                f"passes (--fail-on {fail_on})")
    counts = Counter(v.severity.value.lower() for _f, v in findings)
    by_sev = ", ".join(
        f"{counts[s]} {s}" for s in ("critical", "high", "medium", "low", "info")
        if counts[s]
    )
    files = len({fp for fp, _v in findings})
    verdict = (f"fails (--fail-on {fail_on})" if gate
               else f"passes (--fail-on {fail_on})")
    # Both numbers: files WITH findings, and files examined. The first alone
    # says nothing about coverage.
    return (f"{prog}: {len(findings)} finding(s) [{by_sev}] "
            f"in {files} of {analyzed_files} file(s) — {verdict}")


if __name__ == "__main__":
    sys.exit(main())
