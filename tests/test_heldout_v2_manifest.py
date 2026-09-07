"""The v2 held-out manifest must stay a frozen, checkable artifact.

WHY THIS EXISTS
---------------
v2's whole claim is that its labels were written before the scanner ran. Nothing
about a JSON file makes that true, and nothing but a test keeps it true
afterwards: a prediction quietly edited to match a disappointing run is
indistinguishable, in the file, from one that was right.

So the properties that make this corpus evidence are asserted here -- every
commit is a full sha, every case carries reasoning, every predicted rule exists,
pairs actually differ, and the README quotes no rate over sixteen cases. The
freeze itself is enforced by git history rather than by a test: the commit that
adds this manifest is the parent of the commit that adds results-0.19.1.json.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from o1js_scan.rules import REGISTRY

REPO_ROOT = Path(__file__).resolve().parents[1]
V2 = REPO_ROOT / "research" / "heldout-o1js-v2"
MANIFEST = V2 / "manifest.json"
README = V2 / "README.md"

STATUSES = {"held-out", "development", "regression"}
KINDS = {"single", "pair"}


def _manifest() -> dict:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def _rules_named(case: dict) -> list:
    keys = ("expected_rules", "expected_absent", "predicted_false_positives",
            "expected_delta_rules")
    return [r for k in keys for r in case.get(k, [])]


def test_manifest_is_well_formed():
    m = _manifest()
    assert m["schema"] == 2
    assert m["scanner_version_at_freeze"], "results are meaningless without a freeze point"
    assert len(m["cases"]) >= 10, "a corpus this small is not worth the ceremony"
    ids = [c["id"] for c in m["cases"]]
    assert len(ids) == len(set(ids)), "case ids must be unique"


@pytest.mark.parametrize("case", _manifest()["cases"], ids=lambda c: c["id"])
def test_case_is_pinned_labelled_and_scoped(case):
    assert case["kind"] in KINDS
    assert case["status"] in STATUSES
    assert case["reasoning"].strip(), f"{case['id']}: a prediction without reasoning is a guess"
    assert case["scan_path"], f"{case['id']}: v2 scans exactly the path the label was written from"
    assert not case["scan_path"].startswith("/"), f"{case['id']}: scan_path is repo-relative"

    shas = ([case["commit"]] if case["kind"] == "single"
            else [case["vulnerable_commit"], case["fixed_commit"]])
    for sha in shas:
        assert re.fullmatch(r"[0-9a-f]{40}", sha), (
            f"{case['id']}: {sha!r} must be a full 40-character sha -- an "
            f"abbreviation cannot be compared against `git rev-parse HEAD`"
        )
    if case["kind"] == "pair":
        assert case["vulnerable_commit"] != case["fixed_commit"], (
            f"{case['id']}: a pair whose two sides are the same commit measures nothing"
        )
        assert case["defect"].strip(), f"{case['id']}: a pair must name the defect"
        assert case["provenance"].strip(), (
            f"{case['id']}: a pair's authority is where the fix came from"
        )
        assert case["expected_detected"] == bool(case["expected_delta_rules"])
        if not case["expected_delta_rules"]:
            assert case.get("why_not_modelled", "").strip(), (
                f"{case['id']}: predicting no delta is a claim about coverage and "
                f"has to say which coverage is missing"
            )
    else:
        assert case["label"] in {"vulnerable", "clean"}

    for rule_id in _rules_named(case):
        assert rule_id in REGISTRY, f"{case['id']}: unknown rule {rule_id}"


def test_predictions_do_not_contradict_themselves():
    """A rule cannot be both an expected true positive and a predicted false one."""
    for case in _manifest()["cases"]:
        expected = set(case.get("expected_rules", []))
        predicted_fp = set(case.get("predicted_false_positives", []))
        absent = set(case.get("expected_absent", []))
        assert not (expected & predicted_fp), (
            f"{case['id']}: {sorted(expected & predicted_fp)} is predicted to be both "
            f"correct and a false positive"
        )
        assert not (expected & absent), (
            f"{case['id']}: {sorted(expected & absent)} is expected both to fire and to be absent"
        )


def test_v2_does_not_overlap_the_tuned_or_v1_corpora():
    """A repository the rules were built or measured against is not held out."""
    canary = (REPO_ROOT / "scripts" / "mina_canary.sh").read_text(encoding="utf-8")
    tuned = {r.lower() for r in re.findall(r'"([^"|]+)\|[0-9a-f]{40}\|', canary)}
    v1 = json.loads((REPO_ROOT / "research" / "heldout-o1js" / "manifest.json")
                    .read_text(encoding="utf-8"))
    v1_repos = {c["repo"].lower() for c in v1["cases"]}
    for case in _manifest()["cases"]:
        repo = case["repo"].lower()
        assert repo not in tuned, f"{case['id']}: {case['repo']} is in the calibration corpus"
        assert repo not in v1_repos, f"{case['id']}: {case['repo']} is already a v1 case"
        assert repo != "o1-labs/o1js", (
            f"{case['id']}: o1js upstream is a canary target, not held-out code"
        )


def test_selection_is_reproducible():
    """Someone else has to be able to rebuild the candidate pool."""
    sel = _manifest()["selection"]
    for key in ("index", "query", "date", "filter", "why_a_different_index"):
        assert sel.get(key, "").strip(), f"selection.{key} is what makes the pool checkable"


def test_status_counts_match_the_cases():
    m = _manifest()
    actual = {s: 0 for s in STATUSES}
    for case in m["cases"]:
        actual[case["status"]] += 1
    assert m["status_counts"] == actual


def test_no_aggregate_rate_is_quoted():
    """Sixteen cases, split across two designs, support no rate at all."""
    if not README.is_file():
        pytest.skip("README not written yet")
    text = README.read_text(encoding="utf-8")
    rates = re.findall(r"\b\d{1,3}\s?%\s*(?:recall|precision|accuracy|detection)", text, re.I)
    assert rates == [], f"README quotes a rate over sixteen cases: {rates}"
