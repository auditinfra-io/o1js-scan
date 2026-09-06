#!/usr/bin/env python3
"""Compare scanner output on the held-out corpus against its frozen labels.

Reports per case rather than as a single recall percentage: the denominator is
six, and a percentage over six cases would imply a precision this evidence does
not have.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))


def scan(path: Path) -> list:
    proc = subprocess.run(
        [sys.executable, "-m", "o1js_scan.cli", str(path),
         "--lang", "o1js", "--fail-on", "none", "--json"],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )
    if proc.returncode not in (0, 1):
        raise SystemExit(f"scan failed for {path}: {proc.stderr}")
    return [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", type=Path, required=True)
    ap.add_argument("--corpus", type=Path, required=True)
    ap.add_argument("--json-out", type=Path)
    args = ap.parse_args()

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    out = {"scanner_version": None, "cases": []}
    import o1js_scan
    out["scanner_version"] = o1js_scan.__version__

    for case in manifest["cases"]:
        path = args.corpus / case["repo"].split("/")[-1]
        if not path.is_dir():
            print(f"skip {case['id']}: not checked out")
            continue
        findings = scan(path)
        by_rule = Counter(f["rule_id"] for f in findings)
        highest = sorted(
            {f["severity"] for f in findings},
            key=lambda s: {"high": 0, "medium": 1, "low": 2}.get(s, 3),
        )
        record = {
            "id": case["id"],
            "label": case["label"],
            "expected_rules": case["expected_rules"],
            "observed_rules": dict(sorted(by_rule.items())),
            "total_findings": len(findings),
            "highest_severity": highest[0] if highest else None,
        }
        expected = set(case["expected_rules"])
        observed = set(by_rule)
        record["expected_and_found"] = sorted(expected & observed)
        record["expected_not_found"] = sorted(expected - observed)
        record["unexpected"] = sorted(observed - expected)
        out["cases"].append(record)

        if case["label"] == "clean":
            flag = "clean-negative" if not findings else "FALSE POSITIVES ON NEGATIVE CASE"
        else:
            flag = "flagged" if findings else "MISSED - no finding on a vulnerable case"
        record["outcome"] = flag
        print(f"{case['id']:32} {case['label']:11} {len(findings):4} finding(s)  {flag}")
        if record["expected_not_found"]:
            print(f"    expected but absent: {record['expected_not_found']}")
        if record["unexpected"]:
            print(f"    not predicted:       {record['unexpected']}")

    if args.json_out:
        args.json_out.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
        print(f"\nwrote {args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
