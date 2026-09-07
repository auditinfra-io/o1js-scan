#!/usr/bin/env python3
"""Compare scanner output on the held-out corpus against its frozen labels.

Reports per case rather than as a single recall percentage: the denominator is
six, and a percentage over six cases would imply a precision this evidence does
not have.

FAIL-CLOSED BY DESIGN
---------------------
A case is scanned only if its checkout is at exactly the 40-character commit
the manifest pins, verified here with `git rev-parse HEAD` rather than trusted
from whatever the runner did. Anything else -- a missing directory, a directory
that is not a git checkout, a checkout that drifted to another commit -- is a
hard failure with exit status 2, and no results file is written.

The reason is that this script's output gets recorded as evidence. A run that
silently scanned five of six repositories, or scanned today's default branch
instead of the frozen commit, produces a results file indistinguishable from a
real one. --allow-missing exists for deliberate partial runs; it marks the
output `corpus_complete: false` and lists what was skipped, so an incomplete
run cannot be mistaken for a benchmark later.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

FULL_SHA = re.compile(r"[0-9a-f]{40}")


def scan(path: Path) -> list:
    proc = subprocess.run(
        [sys.executable, "-m", "o1js_scan.cli", str(path),
         "--lang", "o1js", "--fail-on", "none", "--json"],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )
    if proc.returncode not in (0, 1):
        raise SystemExit(f"scan failed for {path}: {proc.stderr}")
    return [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]


def head_commit(path: Path) -> str | None:
    """The commit actually checked out, or None if this is not a git checkout."""
    proc = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        return None
    return proc.stdout.strip()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", type=Path, required=True)
    ap.add_argument("--corpus", type=Path, required=True)
    ap.add_argument("--json-out", type=Path)
    ap.add_argument(
        "--allow-missing", action="store_true",
        help="Downgrade unusable cases from errors to warnings and mark the "
             "run incomplete. Such a run is not a benchmark result.",
    )
    args = ap.parse_args()

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    import o1js_scan
    out = {
        "scanner_version": o1js_scan.__version__,
        "corpus_complete": True,
        "cases": [],
    }

    problems: list[str] = []

    for case in manifest["cases"]:
        expected = case["commit"]
        if not FULL_SHA.fullmatch(expected):
            problems.append(
                f"{case['id']}: manifest commit {expected!r} is not a full "
                f"40-character sha, so the checkout cannot be verified"
            )
            continue

        path = args.corpus / case["repo"].split("/")[-1]
        if not path.is_dir():
            problems.append(f"{case['id']}: not checked out at {path}")
            continue

        actual = head_commit(path)
        if actual is None:
            problems.append(f"{case['id']}: {path} is not a git checkout")
            continue
        if actual != expected:
            problems.append(
                f"{case['id']}: {path} is at {actual}, manifest pins {expected}"
            )
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
            "expected_commit": expected,
            "actual_commit": actual,
            "expected_rules": case["expected_rules"],
            "observed_rules": dict(sorted(by_rule.items())),
            "total_findings": len(findings),
            "highest_severity": highest[0] if highest else None,
        }
        expected_rules = set(case["expected_rules"])
        observed = set(by_rule)
        record["expected_and_found"] = sorted(expected_rules & observed)
        record["expected_not_found"] = sorted(expected_rules - observed)
        record["unexpected"] = sorted(observed - expected_rules)

        if case["label"] == "clean":
            flag = "clean-negative" if not findings else "FALSE POSITIVES ON NEGATIVE CASE"
        else:
            flag = "flagged" if findings else "MISSED - no finding on a vulnerable case"
        record["outcome"] = flag
        out["cases"].append(record)

        print(f"{case['id']:32} {case['label']:11} {len(findings):4} finding(s)  {flag}")
        if record["expected_not_found"]:
            print(f"    expected but absent: {record['expected_not_found']}")
        if record["unexpected"]:
            print(f"    not predicted:       {record['unexpected']}")

    if problems:
        for problem in problems:
            print(f"held-out benchmark: {problem}", file=sys.stderr)
        if not args.allow_missing:
            print(
                f"held-out benchmark: {len(problems)} case(s) could not be "
                f"verified against their pinned commits. No results written -- "
                f"a partial scan recorded as a benchmark is worse than no "
                f"benchmark. Pass --allow-missing for a deliberate partial run.",
                file=sys.stderr,
            )
            return 2
        out["corpus_complete"] = False
        out["skipped"] = problems
        print(
            f"held-out benchmark: INCOMPLETE -- {len(problems)} of "
            f"{len(manifest['cases'])} case(s) skipped. Do not record this as "
            f"a benchmark result.",
            file=sys.stderr,
        )

    if args.json_out:
        args.json_out.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
        print(f"\nwrote {args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
