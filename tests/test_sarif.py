"""Tests for SARIF 2.1.0 output + the CLI --sarif flag."""

from __future__ import annotations

import json

from o1js_scan import Severity, Vulnerability, analyze_file
from o1js_scan.sarif import to_sarif

_DRAIN = """
import { SmartContract, UInt64, PublicKey, method } from 'o1js';
export class C extends SmartContract {
  @method async pay(to: PublicKey, amount: UInt64) {
    this.send({ to: to, amount: amount });
  }
}
"""


def _findings(src, name="src/C.ts"):
    return [(name, v) for v in analyze_file(name, src)]


def test_sarif_top_level_shape():
    doc = to_sarif(_findings(_DRAIN), "0.4.0")
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-schema-2.1.0.json")
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "o1js-scan"
    assert driver["version"] == "0.4.0"
    assert driver["rules"], "must declare at least one rule"


def test_sarif_results_are_wellformed_for_github():
    doc = to_sarif(_findings(_DRAIN), "0.4.0")
    run = doc["runs"][0]
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert run["results"], "expected findings on the drain fixture"
    for res in run["results"]:
        # GitHub code scanning requires ruleId, a message, and a physical location.
        assert res["ruleId"] in rule_ids
        assert res["message"]["text"]
        assert res["level"] in ("error", "warning", "note")
        loc = res["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"]
        assert loc["region"]["startLine"] >= 1
        # security-severity drives the Security-tab severity bucket.
        assert "security-severity" in res["properties"]


def test_sarif_high_maps_to_error_level_and_score():
    doc = to_sarif(_findings(_DRAIN), "0.4.0")
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    high = next(r for r in rules if r["id"] == "O1JS_UNCONSTRAINED_WITNESS")
    assert high["defaultConfiguration"]["level"] == "error"
    assert high["properties"]["security-severity"] == "8.0"


def test_sarif_deduplicates_rules():
    # Two findings of the same rule must yield ONE rule entry, two results.
    findings = [
        ("a.ts", Vulnerability(pattern_name="R", severity=Severity.HIGH,
                               location=(3, 0), rule_id="R", title="t")),
        ("b.ts", Vulnerability(pattern_name="R", severity=Severity.HIGH,
                               location=(9, 0), rule_id="R", title="t")),
    ]
    doc = to_sarif(findings, "0.4.0")
    run = doc["runs"][0]
    assert len(run["tool"]["driver"]["rules"]) == 1
    assert len(run["results"]) == 2
    assert all(res["ruleIndex"] == 0 for res in run["results"])


def test_sarif_clamps_missing_line_to_one():
    findings = [("a.ts", Vulnerability(pattern_name="R", severity=Severity.LOW,
                                       location=None, rule_id="R"))]
    doc = to_sarif(findings, "0.4.0")
    reg = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
    assert reg["startLine"] == 1


def test_sarif_empty_run_is_valid():
    doc = to_sarif([], "0.4.0")
    assert doc["runs"][0]["results"] == []
    assert doc["runs"][0]["tool"]["driver"]["rules"] == []


# ---------------------------------------------------------------------------
# CLI --sarif
# ---------------------------------------------------------------------------

def test_cli_sarif_writes_file_and_keeps_exit_gate(tmp_path):
    from o1js_scan.cli import main

    (tmp_path / "C.ts").write_text(_DRAIN)
    out = tmp_path / "out.sarif"
    rc = main([str(tmp_path), "--sarif", str(out)])
    # SARIF is written even though the high finding still trips the exit gate.
    assert rc == 1
    assert out.exists()
    doc = json.loads(out.read_text())
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"]


def test_cli_sarif_stdout_dash(capsys, tmp_path):
    from o1js_scan.cli import main

    (tmp_path / "C.ts").write_text(_DRAIN)
    main([str(tmp_path), "--sarif", "-"])
    doc = json.loads(capsys.readouterr().out)
    assert doc["runs"][0]["tool"]["driver"]["name"] == "o1js-scan"
