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
    args = ap.parse_args(argv)

    findings = analyze_project(args.path)

    if args.json:
        for fp, v in findings:
            print(json.dumps({
                "file": fp,
                "rule_id": v.rule_id,
                "severity": v.severity.value,
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

    hi = any(v.severity.value in ("CRITICAL", "high") for _f, v in findings)
    return 1 if hi else 0


if __name__ == "__main__":
    sys.exit(main())
