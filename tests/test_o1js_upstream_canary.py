from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from o1js_upstream_report import (  # noqa: E402
    build_summary,
    read_findings,
    sorted_findings,
)


def finding(**updates):
    value = {
        "file": "packages/app/src/main.ts",
        "rule_id": "O1JS_RULE",
        "severity": "MEDIUM",
        "line": 12,
        "title": "Example finding",
    }
    value.update(updates)
    return value


def write_jsonl(path: Path, values) -> None:
    path.write_text("".join(json.dumps(value) + "\n" for value in values), encoding="utf-8")


def test_valid_jsonl_and_empty_production_are_accepted(tmp_path):
    report = tmp_path / "report.jsonl"
    write_jsonl(report, [finding()])
    assert read_findings(report, allow_empty=False) == [finding()]
    report.write_text("", encoding="utf-8")
    assert read_findings(report, allow_empty=True) == []


@pytest.mark.parametrize(
    ("content", "message"),
    [("not-json\n", "malformed JSON"), (json.dumps({"file": "x"}), "missing fields")],
)
def test_invalid_jsonl_is_rejected(tmp_path, content, message):
    report = tmp_path / "report.jsonl"
    report.write_text(content, encoding="utf-8")
    with pytest.raises(ValueError, match=message):
        read_findings(report, allow_empty=False)


def test_empty_all_source_report_is_rejected(tmp_path):
    report = tmp_path / "report.jsonl"
    report.write_text("\n", encoding="utf-8")
    with pytest.raises(ValueError, match="empty report"):
        read_findings(report, allow_empty=False)


def test_sorting_and_summary_counts_are_deterministic():
    values = [
        finding(severity="LOW", file="a.ts", line=1, rule_id="Z"),
        finding(severity="HIGH", file="z.ts", line=2, rule_id="B"),
        finding(severity="MEDIUM", file="a.ts", line=3, rule_id="A"),
        finding(severity="HIGH", file="a.ts", line=3, rule_id="A"),
        finding(severity="HIGH", file="a.ts", line=2, rule_id="C"),
    ]
    assert [(x["severity"], x["file"], x["line"]) for x in sorted_findings(values)] == [
        ("HIGH", "a.ts", 2),
        ("HIGH", "a.ts", 3),
        ("HIGH", "z.ts", 2),
        ("MEDIUM", "a.ts", 3),
        ("LOW", "a.ts", 1),
    ]
    summary = build_summary(values, values, version="0.15.0", commit="abc123")
    assert "production: total=5 HIGH=3 MEDIUM=1 LOW=1 files=2" in summary
    assert "production by rule: A=2, B=1, C=1, Z=1" in summary
    assert summary.index("HIGH C a.ts:2") < summary.index("MEDIUM A a.ts:3")


def test_script_preserves_output_files(tmp_path):
    checkout = tmp_path / "o1js"
    checkout.mkdir()
    subprocess.run(["git", "init", "-q", str(checkout)], check=True)
    subprocess.run(["git", "-C", str(checkout), "config", "user.email", "test@example.com"], check=True)
    subprocess.run(["git", "-C", str(checkout), "config", "user.name", "Test"], check=True)
    (checkout / "README").write_text("fixture", encoding="utf-8")
    subprocess.run(["git", "-C", str(checkout), "add", "README"], check=True)
    subprocess.run(["git", "-C", str(checkout), "commit", "-qm", "fixture"], check=True)

    fake_python = tmp_path / "python"
    fake_python.write_text(
        f"""#!/usr/bin/env bash
if [[ "$1" == "-m" ]]; then
  if [[ " $* " == *" --include-tests "* ]]; then
    echo '{{"file":"tests/a.ts","rule_id":"ALL","severity":"LOW","line":2,"title":"all"}}'
  else
    echo '{{"file":"src/a.ts","rule_id":"PROD","severity":"HIGH","line":7,"title":"prod"}}'
  fi
elif [[ "$1" == "-c" ]]; then
  echo 0.15.0
else
  exec {sys.executable} "$@"
fi
""",
        encoding="utf-8",
    )
    fake_python.chmod(0o755)
    output = tmp_path / "artifacts"
    result = subprocess.run(
        ["bash", str(REPO_ROOT / "scripts/o1js_upstream_canary.sh"), str(checkout), str(output)],
        env={"PYTHON": str(fake_python)},
        text=True,
        capture_output=True,
        check=True,
    )
    assert "HIGH PROD src/a.ts:7" in result.stdout
    assert {path.name for path in output.iterdir()} == {
        "all-findings.jsonl",
        "production-findings.jsonl",
        "summary.txt",
    }


def test_workflow_uploads_reports_and_keeps_canary_triggers():
    workflow = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "actions/upload-artifact@v4" in workflow
    assert "name: o1js-upstream-scan" in workflow
    for filename in ("all-findings.jsonl", "production-findings.jsonl", "summary.txt"):
        assert f"artifacts/o1js-upstream/{filename}" in workflow
    assert "workflow_dispatch:" in workflow
    assert "schedule:" in workflow
    assert "github.event_name == 'workflow_dispatch' || github.event_name == 'schedule'" in workflow
