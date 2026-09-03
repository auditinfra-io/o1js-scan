#!/usr/bin/env python3
"""Capture and verify reproducible scan snapshots over pinned checkouts.

WHY THIS EXISTS
---------------
Both o1js canaries answered a yes/no question and threw the evidence away.
``o1js_upstream_canary`` proved the JSONL stayed parseable; ``mina_canary``
proved a HIGH count matched a budget. Neither recorded *which* findings, so a
rule could swap one finding for another at the same severity and both canaries
would still pass.

A snapshot records every finding at a pinned commit. Verifying it is then an
exact set comparison, and the diff on failure names the findings that appeared
or disappeared instead of a count that moved.

Usage:

    scan_snapshot.py capture SNAPSHOT.json --target NAME=PATH [--target ...]
    scan_snapshot.py verify  SNAPSHOT.json --target NAME=PATH [--target ...]

A target whose name is absent from the snapshot is reported, never silently
ignored; a target present in the snapshot but not supplied is skipped with a
note, so a partial corpus (an unreachable clone) degrades to partial coverage
rather than a false pass.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
# Run against this checkout even when the package is not installed, matching how
# the scan subprocess is invoked below (``python -m`` with cwd=REPO_ROOT).
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

SCHEMA = 1
SEVERITIES = ("high", "medium", "low")


def scan(root: Path, *, include_tests: bool, include_examples: bool) -> List[Dict[str, Any]]:
    """Run the analyzer over ``root`` and return findings with relative paths."""
    argv = [sys.executable, "-m", "o1js_scan.cli", str(root),
            "--lang", "o1js", "--fail-on", "none", "--json"]
    if include_tests:
        argv.append("--include-tests")
    if include_examples:
        argv.append("--include-examples")
    proc = subprocess.run(argv, capture_output=True, text=True, cwd=REPO_ROOT)
    if proc.returncode != 0:
        raise SystemExit(f"scan failed for {root} (exit {proc.returncode}):\n{proc.stderr}")

    findings = []
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        path = Path(item["file"])
        try:
            rel = path.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            rel = path.as_posix()
        findings.append({
            "rule_id": item["rule_id"],
            "severity": str(item["severity"]).lower(),
            "file": rel,
            "line": int(item["line"]),
        })
    return sorted(findings, key=lambda f: (f["file"], f["line"], f["rule_id"], f["severity"]))


def summarize(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    by_severity = Counter(f["severity"] for f in findings)
    return {
        "totals": {
            "findings": len(findings),
            "files": len({f["file"] for f in findings}),
            **{s: by_severity[s] for s in SEVERITIES},
        },
        "by_rule": dict(sorted(Counter(f["rule_id"] for f in findings).items())),
        "findings": findings,
    }


def git_commit(root: Path) -> str:
    proc = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                          capture_output=True, text=True)
    return proc.stdout.strip() if proc.returncode == 0 else ""


def key(f: Dict[str, Any]) -> Tuple:
    return (f["file"], f["line"], f["rule_id"], f["severity"])


def load(path: Path) -> Dict[str, Any]:
    snapshot = json.loads(path.read_text(encoding="utf-8"))
    if snapshot.get("schema") != SCHEMA:
        raise SystemExit(f"{path}: unsupported schema {snapshot.get('schema')!r}")
    return snapshot


def parse_targets(pairs: List[str]) -> Dict[str, Path]:
    out = {}
    for pair in pairs:
        name, _, raw = pair.partition("=")
        if not name or not raw:
            raise SystemExit(f"error: --target must be NAME=PATH, got {pair!r}")
        path = Path(raw)
        if not path.is_dir():
            raise SystemExit(f"error: not a directory: {path}")
        out[name] = path
    return out


def cmd_capture(args) -> int:
    import o1js_scan

    targets = parse_targets(args.target)
    entries = []
    for name, path in targets.items():
        findings = scan(path, include_tests=args.include_tests,
                        include_examples=args.include_examples)
        entries.append({"name": name, "commit": git_commit(path), **summarize(findings)})
        print(f"  {name:34} {len(findings):3} finding(s)")

    snapshot = {
        "schema": SCHEMA,
        "kind": args.kind,
        "captured_with": f"o1js-scan {o1js_scan.__version__}",
        "scan": {
            "lang": "o1js",
            "include_tests": args.include_tests,
            "include_examples": args.include_examples,
            "fail_on": "none",
        },
        "targets": entries,
    }
    args.snapshot.write_text(json.dumps(snapshot, indent=2, sort_keys=False) + "\n",
                             encoding="utf-8")
    print(f"\nwrote {args.snapshot}")
    return 0


def cmd_verify(args) -> int:
    snapshot = load(args.snapshot)
    supplied = parse_targets(args.target)
    recorded = {t["name"]: t for t in snapshot["targets"]}

    unknown = sorted(set(supplied) - set(recorded))
    if unknown:
        print(f"FAIL: target(s) not in the snapshot: {unknown}", file=sys.stderr)
        return 1

    failed = False
    checked = 0
    for name, entry in recorded.items():
        if name not in supplied:
            print(f"skip {name:34} (not supplied)")
            continue
        path = supplied[name]

        commit = git_commit(path)
        if entry.get("commit") and commit and commit != entry["commit"]:
            print(f"FAIL {name:34} commit {commit[:8]} != pinned {entry['commit'][:8]}",
                  file=sys.stderr)
            failed = True
            continue

        found = scan(path, include_tests=snapshot["scan"]["include_tests"],
                     include_examples=snapshot["scan"]["include_examples"])
        checked += 1
        expected = {key(f) for f in entry["findings"]}
        actual = {key(f) for f in found}
        gained, lost = sorted(actual - expected), sorted(expected - actual)
        if gained or lost:
            failed = True
            print(f"FAIL {name:34} +{len(gained)} / -{len(lost)}", file=sys.stderr)
            for f in lost:
                print(f"       LOST  {f[2]} {f[0]}:{f[1]} ({f[3]})", file=sys.stderr)
            for f in gained:
                print(f"       NEW   {f[2]} {f[0]}:{f[1]} ({f[3]})", file=sys.stderr)
        else:
            print(f"ok   {name:34} {len(found):3} finding(s) match")

    if checked == 0:
        print("FAIL: no target was actually verified", file=sys.stderr)
        return 1
    if failed:
        print("\nsnapshot verify: FAIL", file=sys.stderr)
        print("  a LOST finding means a rule stopped firing on pinned, unchanged source",
              file=sys.stderr)
        print("  a NEW finding must be read and classified before the snapshot is updated",
              file=sys.stderr)
        print("  regenerate deliberately with: scan_snapshot.py capture", file=sys.stderr)
        return 1
    print(f"\nsnapshot verify: PASS ({checked} target(s))")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="command", required=True)
    for name in ("capture", "verify"):
        p = sub.add_parser(name)
        p.add_argument("snapshot", type=Path)
        p.add_argument("--target", action="append", default=[], metavar="NAME=PATH",
                       help="a pinned checkout to scan; repeatable")
        if name == "capture":
            p.add_argument("--kind", required=True)
            p.add_argument("--include-tests", action="store_true")
            p.add_argument("--include-examples", action="store_true")
        p.set_defaults(func=cmd_capture if name == "capture" else cmd_verify)
    args = ap.parse_args()
    if not args.target:
        raise SystemExit("error: at least one --target is required")
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
