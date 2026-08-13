#!/usr/bin/env python3
"""Validate and summarize the two o1js upstream canary JSONL reports."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

REQUIRED_FIELDS = {"file", "rule_id", "severity", "line", "title"}
SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
EXAMPLE_FILE_RE = re.compile(r"\.eg\.(?:ts|tsx|js|jsx|mjs|cjs|nr)$")


def read_findings(path: Path, *, allow_empty: bool) -> List[Dict[str, Any]]:
    """Read JSONL, rejecting malformed records and missing triage fields."""
    findings = []
    with path.open(encoding="utf-8") as report:
        for line_number, line in enumerate(report, 1):
            if not line.strip():
                continue
            try:
                finding = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"{path}: malformed JSON on line {line_number}: {error}") from error
            if not isinstance(finding, dict):
                raise ValueError(f"{path}: finding {line_number} is not a JSON object")
            missing = REQUIRED_FIELDS - finding.keys()
            if missing:
                raise ValueError(
                    f"{path}: finding {line_number} is missing fields: {sorted(missing)}"
                )
            findings.append(finding)
    if not findings and not allow_empty:
        raise ValueError("empty report; no upstream syntax was exercised")
    return findings


def sorted_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(
        findings,
        key=lambda item: (
            SEVERITY_ORDER.get(str(item["severity"]).upper(), 3),
            str(item["file"]),
            int(item["line"]),
            str(item["rule_id"]),
        ),
    )


def normalize_path(path: str, root: Path) -> str:
    """Make paths inside the checkout stable across randomized clone locations."""
    candidate = Path(path)
    try:
        resolved_relative = candidate.resolve().relative_to(root.resolve())
    except ValueError:
        # A relative path may already be checkout-relative. Retain it, and also
        # retain unexpected absolute paths rather than obscuring their origin.
        pass
    else:
        candidate = resolved_relative
    return candidate.as_posix()


def normalize_findings(
    findings: List[Dict[str, Any]], root: Path
) -> List[Dict[str, Any]]:
    return [{**item, "file": normalize_path(str(item["file"]), root)} for item in findings]


def is_example_path(path: str) -> bool:
    """Match the scanner's documented example path conventions."""
    normalized = path.replace("\\", "/")
    segments = normalized.split("/")
    return EXAMPLE_FILE_RE.search(normalized) is not None or any(
        segment in {"example", "examples"} for segment in segments[:-1]
    )


def write_findings(path: Path, findings: List[Dict[str, Any]]) -> None:
    """Persist canonical JSONL after path normalization and report filtering."""
    with path.open("w", encoding="utf-8") as report:
        for finding in findings:
            report.write(json.dumps(finding, sort_keys=True, separators=(",", ":")) + "\n")


def count_lines(label: str, findings: List[Dict[str, Any]]) -> List[str]:
    severities = Counter(str(item["severity"]).upper() for item in findings)
    rules = Counter(str(item["rule_id"]) for item in findings)
    files = {str(item["file"]) for item in findings}
    lines = [
        f"{label}: total={len(findings)} HIGH={severities['HIGH']} "
        f"MEDIUM={severities['MEDIUM']} LOW={severities['LOW']} files={len(files)}",
        f"{label} by rule: "
        + (", ".join(f"{rule}={count}" for rule, count in sorted(rules.items())) or "none"),
    ]
    return lines


def finding_line(item: Dict[str, Any]) -> str:
    return (
        f"{str(item['severity']).upper()} {item['rule_id']} "
        f"{item['file']}:{item['line']} \u2014 {item['title']}"
    )


def build_summary(
    all_findings: List[Dict[str, Any]],
    production_findings: List[Dict[str, Any]],
    *,
    version: str,
    commit: str,
) -> str:
    lines = [f"o1js-scan version: {version}", f"upstream o1js commit: {commit}", ""]
    lines.extend(count_lines("all-source", all_findings))
    lines.append("")
    lines.extend(count_lines("production", production_findings))
    lines.extend(["", "production findings:"])
    ordered = sorted_findings(production_findings)
    lines.extend(finding_line(item) for item in ordered)
    if not ordered:
        lines.append("none")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--all", type=Path, required=True, dest="all_report")
    parser.add_argument("--production", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    try:
        all_findings = read_findings(args.all_report, allow_empty=False)
        production = read_findings(args.production, allow_empty=True)
    except ValueError as error:
        print(f"o1js upstream canary: FAIL ({error})", file=sys.stderr)
        return 1

    all_findings = normalize_findings(all_findings, args.root)
    production = [
        item
        for item in normalize_findings(production, args.root)
        if not is_example_path(str(item["file"]))
    ]
    write_findings(args.all_report, all_findings)
    write_findings(args.production, production)

    args.summary.write_text(
        build_summary(
            all_findings, production, version=args.version, commit=args.commit
        ),
        encoding="utf-8",
    )
    for line in count_lines("all-source", all_findings):
        print(line)
    for item in sorted_findings(all_findings):
        if str(item["severity"]).upper() == "HIGH":
            print(f"all-source HIGH: {finding_line(item)}")
    for line in count_lines("production", production):
        print(line)
    for item in sorted_findings(production):
        print(finding_line(item))
    print("o1js upstream canary: PASS (both reports JSONL valid)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
