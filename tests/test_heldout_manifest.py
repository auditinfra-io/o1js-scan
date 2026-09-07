"""The held-out manifest must stay a frozen, checkable artifact.

WHY THIS EXISTS
---------------
A held-out benchmark is only evidence if its labels were fixed before the tool
ran and its corpus is pinned. Both properties live in a JSON file that nothing
would otherwise check, and both are easy to erode by accident — a commit
shortened to an abbreviation, a label quietly widened after a disappointing
run.
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
RESULTS_LATEST = REPO_ROOT / "research" / "heldout-o1js" / "results-0.20.0.json"
TRIAGE = REPO_ROOT / "research" / "heldout-o1js" / "triage-0.19.0.json"
CORPUS_README = REPO_ROOT / "research" / "heldout-o1js" / "README.md"

STATUSES = {"held-out", "development", "regression"}


def _manifest() -> dict:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def test_manifest_is_well_formed():
    m = _manifest()
    assert m["schema"] == 1
    assert m["cases"], "an empty benchmark measures nothing"
    assert m["scanner_version_at_freeze"], "results are meaningless without a freeze point"


@pytest.mark.parametrize("case", _manifest()["cases"], ids=lambda c: c["id"])
def test_case_is_pinned_and_labelled(case):
    assert re.fullmatch(r"[0-9a-f]{40}", case["commit"]), (
        f"{case['id']}: commit must be a full 40-character hex sha. An "
        f"abbreviation is not a pin: it is ambiguous across forks, and it "
        f"cannot be compared against `git rev-parse HEAD` without a repository "
        f"in hand, which is exactly the check the runner needs to make."
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


# ---------------------------------------------------------------------------
# Case status -- the anti-overfitting bookkeeping
# ---------------------------------------------------------------------------
#
# A held-out corpus is spent by using it. The moment a change is developed
# against one of these repositories, that case stops being evidence about
# unseen code and becomes a regression test. Nothing about the file makes that
# transition visible, so the count of genuinely-unseen cases can drift upward
# just by nobody remembering -- which is the direction that flatters the tool.
# These tests make the transition an explicit, checked edit.


@pytest.mark.parametrize("case", _manifest()["cases"], ids=lambda c: c["id"])
def test_case_status_is_declared_and_justified(case):
    status = case.get("status")
    assert status in STATUSES, (
        f"{case['id']}: status must be one of {sorted(STATUSES)}, not {status!r}"
    )
    if status != "held-out":
        assert case.get("status_reason", "").strip(), (
            f"{case['id']}: a case that is no longer held out must say what "
            f"burned it -- otherwise the corpus looks smaller for no recorded "
            f"reason and someone will move it back"
        )


def test_status_semantics_are_documented():
    m = _manifest()
    assert set(m["status_semantics"]) == STATUSES, (
        "every status a case may carry needs a written meaning in the manifest"
    )
    for status, text in m["status_semantics"].items():
        assert text.strip(), f"{status}: an undefined status is not a status"


def test_declared_status_counts_match_the_cases():
    """The declared count is the tripwire; deriving it would defeat the point."""
    m = _manifest()
    declared = m["status_counts"]
    assert set(declared) == STATUSES
    actual = {status: 0 for status in STATUSES}
    for case in m["cases"]:
        actual[case["status"]] += 1
    assert declared == actual, (
        f"status_counts says {declared} but the cases are {actual}. If a case "
        f"changed status, update the count deliberately -- and check the "
        f"corpus README, which quotes the held-out figure in prose."
    )


def test_the_corpus_readme_quotes_the_real_held_out_count():
    """Prose drifts from data silently; this is the one number that matters."""
    held_out = sum(c["status"] == "held-out" for c in _manifest()["cases"])
    words = {1: "One", 2: "Two", 3: "Three", 4: "Four", 5: "Five",
             6: "Six", 7: "Seven", 8: "Eight", 9: "Nine", 10: "Ten"}
    readme = CORPUS_README.read_text(encoding="utf-8")
    claim = f"{words[held_out]} cases remain genuinely held out"
    assert claim in readme, (
        f"the corpus README must state {claim!r}; {held_out} of "
        f"{len(_manifest()['cases'])} cases are still unseen"
    )


# ---------------------------------------------------------------------------
# Triage
# ---------------------------------------------------------------------------

def test_every_unexpected_finding_is_triaged():
    """An untriaged finding is counted as nothing, which is a silent verdict.

    `unexpected` means only that the frozen labels did not predict it. Four of
    the six cases here carry a real defect in a file the labelling never read,
    so reading the unexpected column as a false-positive count is wrong in both
    directions. The triage file is what makes it readable at all.
    """
    results = json.loads(RESULTS_LATEST.read_text(encoding="utf-8"))
    triage = json.loads(TRIAGE.read_text(encoding="utf-8"))
    # The triage file keeps its 0.19.0 stamp -- that is when it was started --
    # and carries the findings the 0.20.0 gate fix added, which its `summary`
    # note records. What must hold is coverage of the current run.
    assert triage["summary"]["note"].strip()

    triaged = {(f["case"], f["rule_id"]) for f in triage["findings"]}
    for case in results["cases"]:
        for rule_id in case["unexpected"]:
            assert (case["id"], rule_id) in triaged, (
                f"{case['id']}: {rule_id} fired unpredicted and was never "
                f"classified as a true or false positive"
            )

    total = sum(len(f["locations"]) for f in triage["findings"])
    assert total == triage["summary"]["unexpected_findings"]
    by_disposition = {"true_positive": 0, "false_positive": 0}
    for finding in triage["findings"]:
        assert finding["disposition"] in by_disposition, (
            f"{finding['locations'][0]}: unknown disposition "
            f"{finding['disposition']!r}"
        )
        assert finding["reasoning"].strip(), "a verdict without reasoning is a guess"
        by_disposition[finding["disposition"]] += len(finding["locations"])
    assert by_disposition["true_positive"] == triage["summary"]["true_positive"]
    assert by_disposition["false_positive"] == triage["summary"]["false_positive"]
