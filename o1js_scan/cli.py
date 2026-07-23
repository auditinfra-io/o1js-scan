"""Command-line entry point for o1js-scan.

    o1js-scan <path> [--json | --sarif [FILE]] [--fail-on LEVEL]

Exits 1 when a finding at or above the ``--fail-on`` level (default ``high``)
is present, 0 otherwise, and 2 when the scan path does not exist.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import List, Optional

from . import __version__
from .lexer import analyze_project
from .vuln import meets_threshold

_FAIL_ON_CHOICES = ("critical", "high", "medium", "low", "none")


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="o1js-scan",
        description="o1js (Mina/Kimchi) zkApp application-layer soundness scanner.",
    )
    ap.add_argument("path", help="file or directory to scan")
    ap.add_argument("--version", action="version", version=f"o1js-scan {__version__}")
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
        print(f"o1js-scan: path not found: {args.path}", file=sys.stderr)
        return 2

    findings = analyze_project(args.path)

    gate = any(meets_threshold(v.severity.value, args.fail_on) for _f, v in findings)

    # SARIF is written even when the exit gate trips below, so the CI upload
    # step still runs on a repo that has high findings.
    if args.sarif is not None:
        from .sarif import to_sarif

        doc = json.dumps(to_sarif(findings, __version__), indent=2)
        if args.sarif == "-":
            # SARIF owns stdout in this mode; skip the other reporters so the
            # document parses cleanly when piped to the upload action.
            print(doc)
            return 1 if gate else 0
        Path(args.sarif).write_text(doc, encoding="utf-8")
        print(f"o1js-scan: wrote SARIF to {args.sarif}", file=sys.stderr)

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

    print(_summary(findings, args.fail_on, gate), file=sys.stderr)
    return 1 if gate else 0


def _summary(findings, fail_on: str, gate: bool) -> str:
    """One-line stderr summary: counts by severity and the gate outcome."""
    if not findings:
        return "o1js-scan: no findings (or no o1js files found)"
    counts = Counter(v.severity.value.lower() for _f, v in findings)
    by_sev = ", ".join(
        f"{counts[s]} {s}" for s in ("critical", "high", "medium", "low", "info")
        if counts[s]
    )
    files = len({fp for fp, _v in findings})
    verdict = (f"fails (--fail-on {fail_on})" if gate
               else f"passes (--fail-on {fail_on})")
    return (f"o1js-scan: {len(findings)} finding(s) [{by_sev}] "
            f"in {files} file(s) — {verdict}")


if __name__ == "__main__":
    sys.exit(main())
