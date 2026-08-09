"""SARIF 2.1.0 output for o1js-scan.

Emits a SARIF log that GitHub code scanning ingests (the `github/codeql-action/
upload-sarif` action), so findings surface as annotations on the PR diff and as
alerts in the repository's Security tab. Dependency-free — pure dict → JSON.
"""

from __future__ import annotations

import os
from typing import Dict, List, Tuple

from .vuln import Severity, Vulnerability

SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)
INFO_URI = "https://github.com/auditinfra-io/o1js-scan"

# severity -> (SARIF level, GitHub security-severity score)
# GitHub buckets security-severity as: >=9 critical, 7-8.9 high, 4-6.9 medium, <4 low.
_LEVEL = {
    "critical": ("error", "9.5"),
    "high": ("error", "8.0"),
    "medium": ("warning", "5.0"),
    "low": ("note", "3.0"),
    "info": ("note", "1.0"),
}


def _sev_str(v: Vulnerability) -> str:
    return v.severity.value if isinstance(v.severity, Severity) else str(v.severity)


def _uri(filepath: str) -> str:
    """Normalize a scanned path to a repo-relative URI GitHub can map to a file."""
    p = filepath
    if os.path.isabs(p):
        try:
            p = os.path.relpath(p, os.getcwd())
        except ValueError:
            pass
    return p.replace(os.sep, "/").lstrip("./") or filepath


def to_sarif(
    findings: List[Tuple[str, Vulnerability]], version: str, stats=None,
) -> Dict:
    """Build a SARIF 2.1.0 log from ``[(filepath, Vulnerability), ...]``.

    ``stats`` (a :class:`o1js_scan.paths.ScanStats`) is recorded under
    ``invocation.properties`` so a consumer can see that files were skipped as
    test code or downgraded as examples, rather than inferring silence.
    """
    rule_index: Dict[str, int] = {}
    rules: List[Dict] = []
    results: List[Dict] = []

    for filepath, v in findings:
        rid = v.rule_id or v.pattern_name
        sev = _sev_str(v).lower()
        level, sec_sev = _LEVEL.get(sev, ("warning", "5.0"))

        if rid not in rule_index:
            rule_index[rid] = len(rules)
            rules.append({
                "id": rid,
                "name": rid,
                "shortDescription": {"text": (v.title or rid)[:200]},
                "fullDescription": {"text": v.description or v.title or rid},
                "helpUri": INFO_URI,
                "defaultConfiguration": {"level": level},
                "properties": {
                    "security-severity": sec_sev,
                    "tags": ["security", "zk", "o1js"],
                },
            })

        line = max(1, (v.location or [1])[0] or 1)
        result = {
            "ruleId": rid,
            "ruleIndex": rule_index[rid],
            "level": level,
            "message": {"text": v.title or v.description or rid},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": _uri(filepath)},
                    "region": {"startLine": line},
                },
            }],
            "properties": {"security-severity": sec_sev},
        }
        semantic_path = (v.evidence or {}).get("semantic_path")
        if semantic_path:
            locations = []
            for step in semantic_path.get("flow", []):
                # SemanticFacts emits only analyzer-observed locations.  Be
                # defensive for manually-created Vulnerability objects.
                line_number = step.get("line")
                if not isinstance(line_number, int) or line_number < 1:
                    continue
                locations.append({
                    "location": {
                        "message": {"text": step.get("label", step.get("kind", "flow"))},
                        "physicalLocation": {
                            "artifactLocation": {"uri": _uri(filepath)},
                            "region": {"startLine": line_number},
                        },
                    },
                })
            if locations:
                result["codeFlows"] = [{
                    "message": {"text": "Prover-controlled witness to state-changing effect"},
                    "threadFlows": [{"locations": locations}],
                }]
        results.append(result)

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "o1js-scan",
                    "informationUri": INFO_URI,
                    "version": version,
                    "rules": rules,
                },
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": True,
                "properties": {
                    "skippedTestFiles": getattr(stats, "skipped_test_files", 0),
                    "downgradedExampleFindings": getattr(
                        stats, "downgraded_example_findings", 0),
                },
            }],
        }],
    }
