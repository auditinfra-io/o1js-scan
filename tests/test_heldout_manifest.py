"""The held-out manifest must stay a frozen, checkable artifact.

WHY THIS EXISTS
---------------
A held-out benchmark is only evidence if its labels were fixed before the tool
ran and its corpus is pinned. Both properties live in a JSON file that nothing
would otherwise check, and both are easy to erode by accident — a commit
shortened to 8 characters, a label quietly widened after a disappointing run.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from o1js_scan.rules import REGISTRY

REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFEST = REPO_ROOT / "research" / "heldout-o1js" / "manifest.json"
RESULTS = REPO_ROOT / "research" / "heldout-o1js" / "results-0.18.0.json"


def _manifest() -> dict:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def test_manifest_is_well_formed():
    m = _manifest()
    assert m["schema"] == 1
    assert m["cases"], "an empty benchmark measures nothing"
    assert m["scanner_version_at_freeze"], "results are meaningless without a freeze point"


@pytest.mark.parametrize("case", _manifest()["cases"], ids=lambda c: c["id"])
def test_case_is_pinned_and_labelled(case):
    assert re.fullmatch(r"[0-9a-f]{8,40}", case["commit"]), (
        f"{case['id']}: commit must be a hex sha so the corpus is reproducible"
    )
    assert case["label"] in {"vulnerable", "clean"}
    assert case["reasoning"].strip(), f"{case['id']}: a label without reasoning is not a label"
    for rule_id in case["expected_rules"]:
        assert rule_id in REGISTRY, f"{case['id']}: unknown rule {rule_id}"
    for rule_id in case.get("expected_absent", []):
        assert rule_id in REGISTRY, f"{case['id']}: unknown rule {rule_id}"


def test_held_out_cases_do_not_overlap_the_calibration_corpus():
    """A repository used to tune the rules is not held out from them."""
    canary = (REPO_ROOT / "scripts" / "mina_canary.sh").read_text(encoding="utf-8")
    tuned = {
        repo.lower() for repo in re.findall(r'"([^"|]+)\|[0-9a-f]{40}\|', canary)
    }
    for case in _manifest()["cases"]:
        assert case["repo"].lower() not in tuned, (
            f"{case['id']}: {case['repo']} is in the calibration corpus, so it "
            f"cannot also be held out"
        )


def test_recorded_results_match_the_manifest_cases():
    results = json.loads(RESULTS.read_text(encoding="utf-8"))
    assert results["scanner_version"] == _manifest()["scanner_version_at_freeze"], (
        "the recorded baseline was produced by a different version than the "
        "manifest claims it was frozen at"
    )
    assert {c["id"] for c in results["cases"]} == {c["id"] for c in _manifest()["cases"]}


def test_no_headline_percentage_is_quoted():
    """Six cases cannot support a recall figure; the README must not imply one."""
    readme = (REPO_ROOT / "research" / "heldout-o1js" / "README.md").read_text(encoding="utf-8")
    percentages = re.findall(r"\b\d{1,3}\s?%\s*(?:recall|precision|accuracy)", readme, re.I)
    assert percentages == [], f"README quotes a rate over six cases: {percentages}"
