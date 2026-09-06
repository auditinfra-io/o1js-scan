"""The composite Action must gate what it reports, and must not hide breakage.

WHY THIS EXISTS
---------------
Two defects motivated these tests, both invisible to every other check:

* the scan step ended in ``|| true``, which suppressed the non-zero exit that
  findings cause — and equally suppressed a bad path, a CLI usage error, or a
  crash. A broken scan reported as a clean one is the worst failure mode a
  security action has, because the SARIF upload then publishes an empty report.

* the reporting pass applied ``--include-tests`` / ``--include-examples`` but
  the enforcement pass did not, so the report and the exit code could describe
  different source sets.

These assert the shape of ``action.yml`` rather than executing a workflow,
which needs no GitHub runner and still fails on the regressions above.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
ACTION = REPO_ROOT / "action.yml"


def _action() -> dict:
    return yaml.safe_load(ACTION.read_text(encoding="utf-8"))


def _steps() -> list:
    return _action()["runs"]["steps"]


def _step(name_fragment: str) -> dict:
    for step in _steps():
        if name_fragment.lower() in str(step.get("name", "")).lower():
            return step
    raise AssertionError(f"no step matching {name_fragment!r}")


def _scan_step() -> dict:
    return _step("Run o1js-scan")


def _gate_step() -> dict:
    return _step("Enforce finding gate")


# ───────────────────────────────────────────────────────────────────
# Operational failures must survive
# ───────────────────────────────────────────────────────────────────

def _code(run: str) -> str:
    """Drop comment lines, so prose about `|| true` is not mistaken for it."""
    return "\n".join(
        line for line in run.splitlines() if not line.lstrip().startswith("#")
    )


def test_no_step_swallows_failures_with_blanket_true():
    """`|| true` on a scan turns a broken run into a clean report."""
    for step in _steps():
        run = _code(str(step.get("run", "")))
        assert "|| true" not in run, (
            f"step {step.get('name')!r} suppresses failures with `|| true`; use "
            f"--fail-on none so findings do not fail the step while operational "
            f"errors still do"
        )


def test_scan_steps_use_pipefail():
    """Without `set -e`, a failing scan mid-script still exits 0."""
    for step in (_scan_step(), _gate_step()):
        assert "set -euo pipefail" in str(step["run"]), (
            f"step {step['name']!r} must fail on the first error"
        )


def test_reporting_pass_disables_the_finding_gate():
    """Findings must not block SARIF generation, so the upload has a file."""
    run = str(_scan_step()["run"])
    assert "--fail-on none --sarif" in run


# ───────────────────────────────────────────────────────────────────
# Report and gate must see the same sources
# ───────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("flag", ["--include-tests", "--include-examples"])
def test_both_passes_honor_the_include_flags(flag):
    for step in (_scan_step(), _gate_step()):
        assert flag in str(step["run"]), (
            f"{step['name']!r} ignores {flag}; the report and the gate would "
            f"analyze different sources"
        )


def test_both_passes_build_the_same_argument_array():
    """Same construction in both steps, so the two cannot drift."""
    build = re.compile(
        r'ARGS=\("\$SCAN_PATH" --lang "\$LANG_INPUT"\).*?'
        r'INCLUDE_TESTS.*?--include-tests.*?'
        r'INCLUDE_EXAMPLES.*?--include-examples',
        re.S,
    )
    for step in (_scan_step(), _gate_step()):
        assert build.search(str(step["run"])), (
            f"{step['name']!r} does not build the shared ARGS array"
        )


# ───────────────────────────────────────────────────────────────────
# Injection safety
# ───────────────────────────────────────────────────────────────────

def test_inputs_reach_scripts_through_the_environment():
    """A composite action interpolates ${{ }} before bash parses the script.

    An input containing shell metacharacters would therefore execute. Every
    input must arrive via `env:` instead.
    """
    for step in _steps():
        run = str(step.get("run", ""))
        if not run:
            continue
        interpolated = re.findall(r"\$\{\{\s*(inputs\.[\w-]+)\s*\}\}", run)
        assert interpolated == [], (
            f"step {step.get('name')!r} interpolates {interpolated} directly "
            f"into a shell script; pass it through `env:` instead"
        )


# ───────────────────────────────────────────────────────────────────
# The severity gate
# ───────────────────────────────────────────────────────────────────

def test_fail_on_input_exists_with_a_non_gating_default():
    inputs = _action()["inputs"]
    assert "fail-on" in inputs
    assert inputs["fail-on"]["default"] == "none", (
        "the Action must not start failing builds for users who did not ask"
    )


def test_gate_uses_the_configured_severity():
    assert '--fail-on "$GATE"' in str(_gate_step()["run"])


def test_gate_is_skipped_when_no_severity_is_requested():
    assert _gate_step()["if"].strip() == "${{ steps.scan.outputs.gate != 'none' }}"


def test_legacy_fail_on_findings_still_maps_to_high():
    """Kept for one release; must keep behaving like the old high gate."""
    inputs = _action()["inputs"]
    assert "fail-on-findings" in inputs, "the deprecated input was removed too early"
    assert "DEPRECATED" in inputs["fail-on-findings"]["description"]
    run = str(_scan_step()["run"])
    assert '"$FAIL_ON_FINDINGS" = "true"' in run and 'GATE="high"' in run


def test_deprecation_is_announced_to_the_user():
    assert "::warning::" in str(_scan_step()["run"])
