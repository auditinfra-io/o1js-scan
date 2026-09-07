#!/usr/bin/env python3
"""Run the v2 held-out corpus and compare it against its frozen labels.

Two things differ from the v1 reporter, and both come from what v1's triage
found out the hard way.

SCOPE. Each case names a `scan_path`, and only that path is scanned. In v1 the
labels were written from one file per repository but the scan covered the whole
repository, so eight of twelve unpredicted findings turned out to be real
defects in files the labelling had never opened -- which made the "unexpected"
column unreadable in both directions. Scoping the scan to the labelled file
makes an unpredicted finding mean "the label was wrong about this code" rather
than "the label never saw this code".

PAIRS. Half the corpus is (vulnerable commit, fixed commit) pairs where one
audit fix is the only difference. For those the measurement is the delta: which
rules fire on the vulnerable side and not the fixed one. A pair holds the
repository, the author and the surrounding code constant, so a delta is
attributable to the constraint that changed -- and a null delta is a clean,
falsifiable statement that the analyzer does not model that defect class.

Fail-closed on the same terms as the v1 runner: every side of every case must be
checked out at exactly the 40-character commit the manifest pins, verified here
with `git rev-parse HEAD`, or the run exits non-zero and writes nothing.
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


def git(path: Path, *args: str) -> tuple[int, str]:
    proc = subprocess.run(["git", "-C", str(path), *args],
                          capture_output=True, text=True)
    return proc.returncode, proc.stdout.strip()


def scan(path: Path) -> list:
    proc = subprocess.run(
        [sys.executable, "-m", "o1js_scan.cli", str(path),
         "--lang", "o1js", "--fail-on", "none", "--json"],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )
    if proc.returncode not in (0, 1):
        raise SystemExit(f"scan failed for {path}: {proc.stderr}")
    return [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]


def checkout_and_scan(corpus: Path, repo: str, commit: str, scan_path: str,
                      problems: list, case_id: str, side: str) -> dict | None:
    """Check out one side of one case and scan just its scan_path."""
    if not FULL_SHA.fullmatch(commit):
        problems.append(f"{case_id}/{side}: {commit!r} is not a full 40-character sha")
        return None
    root = corpus / repo.split("/")[-1]
    if not (root / ".git").is_dir():
        problems.append(f"{case_id}/{side}: {root} is not a git checkout")
        return None
    rc, _ = git(root, "checkout", "-q", "--detach", commit)
    if rc != 0:
        problems.append(f"{case_id}/{side}: cannot check out {commit} in {root}")
        return None
    rc, head = git(root, "rev-parse", "HEAD")
    if rc != 0 or head != commit:
        problems.append(f"{case_id}/{side}: {root} is at {head}, manifest pins {commit}")
        return None
    target = root / scan_path
    if not target.exists():
        problems.append(f"{case_id}/{side}: {scan_path} does not exist at {commit[:12]}")
        return None
    findings = scan(target)
    return {
        "commit": commit,
        "actual_commit": head,
        "observed_rules": dict(sorted(Counter(f["rule_id"] for f in findings).items())),
        "total_findings": len(findings),
        "severities": dict(sorted(Counter(f["severity"] for f in findings).items())),
    }


def report_single(case: dict, side: dict) -> dict:
    expected = set(case["expected_rules"])
    observed = set(side["observed_rules"])
    predicted_fp = set(case.get("predicted_false_positives", []))
    record = {
        "id": case["id"], "kind": "single", "repo": case["repo"],
        "scan_path": case["scan_path"], "label": case["label"],
        **side,
        "expected_rules": case["expected_rules"],
        "expected_and_found": sorted(expected & observed),
        "expected_not_found": sorted(expected - observed),
        "unexpected": sorted(observed - expected - predicted_fp),
    }
    if predicted_fp:
        record["predicted_false_positives"] = sorted(predicted_fp)
        record["predicted_fp_confirmed"] = sorted(predicted_fp & observed)
        record["predicted_fp_absent"] = sorted(predicted_fp - observed)
    absent = set(case.get("expected_absent", []))
    if absent:
        record["expected_absent_violated"] = sorted(absent & observed)
    if case["label"] == "clean":
        record["outcome"] = (
            "clean-negative" if not observed - predicted_fp
            else "UNPREDICTED FINDING ON A CLEAN CASE"
        )
    else:
        record["outcome"] = "flagged" if observed else "MISSED - no finding on a vulnerable case"
    return record


def report_pair(case: dict, vuln: dict, fixed: dict) -> dict:
    delta = Counter(vuln["observed_rules"]) - Counter(fixed["observed_rules"])
    reverse = Counter(fixed["observed_rules"]) - Counter(vuln["observed_rules"])
    expected = set(case["expected_delta_rules"])
    record = {
        "id": case["id"], "kind": "pair", "repo": case["repo"],
        "scan_path": case["scan_path"], "defect": case["defect"],
        "vulnerable": vuln, "fixed": fixed,
        "delta_rules": dict(sorted(delta.items())),
        "reverse_delta_rules": dict(sorted(reverse.items())),
        "expected_delta_rules": case["expected_delta_rules"],
    }
    record["delta_matches_prediction"] = set(delta) == expected
    if not delta and not expected:
        record["outcome"] = "no delta, as predicted - defect class not modelled"
    elif set(delta) == expected:
        record["outcome"] = "delta as predicted"
    elif delta and not expected:
        record["outcome"] = "UNPREDICTED DETECTION - the fix changed findings"
    else:
        record["outcome"] = "PREDICTED DELTA NOT OBSERVED"
    return record


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", type=Path, required=True)
    ap.add_argument("--corpus", type=Path, required=True)
    ap.add_argument("--json-out", type=Path)
    ap.add_argument("--allow-missing", action="store_true",
                    help="Downgrade unusable cases to warnings and mark the run "
                         "incomplete. Such a run is not a benchmark result.")
    args = ap.parse_args()

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    import o1js_scan
    out = {"scanner_version": o1js_scan.__version__, "corpus_complete": True, "cases": []}
    problems: list = []

    for case in manifest["cases"]:
        if case["kind"] == "single":
            side = checkout_and_scan(args.corpus, case["repo"], case["commit"],
                                     case["scan_path"], problems, case["id"], "single")
            if side is None:
                continue
            record = report_single(case, side)
        else:
            vuln = checkout_and_scan(args.corpus, case["repo"], case["vulnerable_commit"],
                                     case["scan_path"], problems, case["id"], "vulnerable")
            fixed = checkout_and_scan(args.corpus, case["repo"], case["fixed_commit"],
                                      case["scan_path"], problems, case["id"], "fixed")
            if vuln is None or fixed is None:
                continue
            record = report_pair(case, vuln, fixed)
        out["cases"].append(record)
        print(f"{record['id']:34} {record['kind']:7} {record['outcome']}")
        for key in ("expected_not_found", "unexpected", "expected_absent_violated",
                    "predicted_fp_confirmed", "predicted_fp_absent"):
            if record.get(key):
                print(f"    {key}: {record[key]}")

    if problems:
        for problem in problems:
            print(f"held-out v2: {problem}", file=sys.stderr)
        if not args.allow_missing:
            print(f"held-out v2: {len(problems)} case side(s) could not be verified "
                  f"against their pinned commits. No results written.", file=sys.stderr)
            return 2
        out["corpus_complete"] = False
        out["skipped"] = problems
        print(f"held-out v2: INCOMPLETE -- {len(problems)} side(s) skipped. "
              f"Do not record this as a benchmark result.", file=sys.stderr)

    if args.json_out:
        args.json_out.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
        print(f"\nwrote {args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
