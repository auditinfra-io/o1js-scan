"""Command-line entry point for o1js-scan.

    o1js-scan <path> [--json]

Exits 1 when any high/critical finding is present (CI-friendly), else 0.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from .lexer import analyze_project


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="o1js-scan",
        description="o1js (Mina/Kimchi) zkApp application-layer soundness scanner.",
    )
    ap.add_argument("path", help="file or directory to scan")
    ap.add_argument("--json", action="store_true", help="emit JSONL findings")
    ap.add_argument(
        "--sarif", nargs="?", const="o1js-scan.sarif", default=None, metavar="FILE",
        help="write SARIF 2.1.0 to FILE (default o1js-scan.sarif; '-' for stdout) "
             "for GitHub code scanning",
    )
    args = ap.parse_args(argv)

    # Fail loudly on a missing path. Otherwise a typo'd scan target silently
    # produces zero findings and exit 0 — a green CI run that scanned nothing.
    if not Path(args.path).exists():
        print(f"o1js-scan: path not found: {args.path}", file=sys.stderr)
        return 2

    findings = analyze_project(args.path)

    # SARIF is written even when the exit gate trips below, so the CI upload
    # step still runs on a repo that has high findings.
    if args.sarif is not None:
        from . import __version__
        from .sarif import to_sarif

        doc = json.dumps(to_sarif(findings, __version__), indent=2)
        if args.sarif == "-":
            # SARIF owns stdout in this mode; skip the other reporters so the
            # document parses cleanly when piped to the upload action.
            print(doc)
            hi = any(v.severity.value.lower() in ("critical", "high") for _f, v in findings)
            return 1 if hi else 0
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
        if not findings:
            print("o1js-scan: no findings (or no o1js files found)", file=sys.stderr)
        for fp, v in findings:
            line = (v.location or [0])[0]
            print(f"{v.severity.value.upper():<8} {v.rule_id:<34} "
                  f"{Path(fp).name}:{line}  fn={v.function}  {v.title}")

    hi = any(v.severity.value.lower() in ("critical", "high") for _f, v in findings)
    return 1 if hi else 0


if __name__ == "__main__":
    sys.exit(main())
