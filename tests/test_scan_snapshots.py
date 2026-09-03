"""The committed scan snapshots must stay bound to the canaries they describe.

WHY THIS EXISTS
---------------
Three artifacts describe the same pinned corpus, and until now nothing checked
that they agreed:

* ``scripts/mina_canary.sh`` — a bash array of ``repo|sha|HIGH budget``
* ``docs/mina_calibration.md`` — the table a reader triages findings from
* ``tests/fixtures/mina_benchmark.json`` — the recorded findings

A budget raised in the canary to silence a new finding, without the
classification the calibration doc promises, used to be invisible. So did a
snapshot regenerated against a moved commit. These tests make each of those a
failure, offline — the network-bound half of the check is
``scripts/scan_snapshot.py verify``, run by the weekly canaries.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "tests" / "fixtures"
MINA_SNAPSHOT = FIXTURES / "mina_benchmark.json"
RELEASE_SNAPSHOT = FIXTURES / "o1js_release_matrix.json"

# The one file that exists in o1js 3.0.0 (Mesa) and not in 2.15.0: the
# 32-state-field example that Mesa's raised MAX_ZKAPP_STATE_FIELDS made possible.
MESA_ONLY_SOURCE = "src/examples/zkapps/big-state-zkapp.ts"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _implemented_rule_ids() -> set:
    src = "\n".join(
        p.read_text(encoding="utf-8") for p in (REPO_ROOT / "o1js_scan").glob("*.py")
    )
    return set(re.findall(r'rule_id\s*=\s*["\']([A-Za-z][A-Za-z0-9_]+)["\']', src))


def _canary_pins() -> dict:
    """``{repo basename: (sha, HIGH budget)}`` from the canary's bash array."""
    text = (REPO_ROOT / "scripts" / "mina_canary.sh").read_text(encoding="utf-8")
    pins = {}
    for repo, sha, budget in re.findall(r'"([^"|]+)\|([0-9a-f]{40})\|(\d+)"', text):
        pins[repo.split("/")[-1]] = (sha, int(budget))
    return pins


def _calibration_rows() -> dict:
    """``{repo basename: (short sha, HIGH budget)}`` from the corpus table."""
    text = (REPO_ROOT / "docs" / "mina_calibration.md").read_text(encoding="utf-8")
    rows = {}
    for repo, sha, budget in re.findall(
        r"^\|\s*([\w.-]+/[\w.-]+)\s*\|\s*`([0-9a-f]{7,40})`\s*\|\s*(\d+)\s*\|$", text, re.M
    ):
        rows[repo.split("/")[-1]] = (sha, int(budget))
    return rows


# ───────────────────────────────────────────────────────────────────
# Both snapshots: shape and internal consistency
# ───────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("path", [MINA_SNAPSHOT, RELEASE_SNAPSHOT], ids=lambda p: p.name)
def test_snapshot_is_well_formed(path):
    snapshot = _load(path)
    assert snapshot["schema"] == 1
    assert snapshot["targets"], "a snapshot with no targets verifies nothing"
    for target in snapshot["targets"]:
        assert target["name"]
        assert re.fullmatch(r"[0-9a-f]{40}", target["commit"]), (
            f"{target['name']}: snapshot must pin a full commit sha"
        )


@pytest.mark.parametrize("path", [MINA_SNAPSHOT, RELEASE_SNAPSHOT], ids=lambda p: p.name)
def test_snapshot_summaries_match_their_findings(path):
    """Totals are derived, not asserted — a hand-edited count is a lie."""
    for target in _load(path)["targets"]:
        findings = target["findings"]
        by_severity = Counter(f["severity"] for f in findings)
        assert target["totals"]["findings"] == len(findings), target["name"]
        assert target["totals"]["files"] == len({f["file"] for f in findings}), target["name"]
        for severity in ("high", "medium", "low"):
            assert target["totals"][severity] == by_severity[severity], (
                f"{target['name']}: {severity} total disagrees with the findings"
            )
        assert target["by_rule"] == dict(
            sorted(Counter(f["rule_id"] for f in findings).items())
        ), target["name"]


@pytest.mark.parametrize("path", [MINA_SNAPSHOT, RELEASE_SNAPSHOT], ids=lambda p: p.name)
def test_snapshot_rules_are_all_implemented(path):
    """A snapshot naming a rule the analyzer cannot emit is stale."""
    implemented = _implemented_rule_ids()
    recorded = {f["rule_id"] for t in _load(path)["targets"] for f in t["findings"]}
    assert recorded - implemented == set()


# ───────────────────────────────────────────────────────────────────
# Mina snapshot ↔ canary ↔ calibration doc
# ───────────────────────────────────────────────────────────────────

def test_mina_snapshot_covers_exactly_the_canary_corpus():
    recorded = {t["name"] for t in _load(MINA_SNAPSHOT)["targets"]}
    assert recorded == set(_canary_pins())


def test_mina_snapshot_commits_match_the_canary_pins():
    pins = _canary_pins()
    for target in _load(MINA_SNAPSHOT)["targets"]:
        assert target["commit"] == pins[target["name"]][0], (
            f"{target['name']}: snapshot was captured at a different commit than "
            f"the canary pins; recapture against the pinned sha or move the pin "
            f"deliberately"
        )


def test_mina_snapshot_high_counts_match_the_canary_budgets():
    """The budget is the number of HIGH findings actually read and classified."""
    pins = _canary_pins()
    for target in _load(MINA_SNAPSHOT)["targets"]:
        assert target["totals"]["high"] == pins[target["name"]][1], (
            f"{target['name']}: {target['totals']['high']} HIGH in the snapshot vs "
            f"budget {pins[target['name']][1]}. Raising a budget without classifying "
            f"the finding in docs/mina_calibration.md is what this test forbids."
        )


def test_calibration_doc_matches_the_canary():
    """The table a reader triages from must describe the corpus that is scanned."""
    pins, rows = _canary_pins(), _calibration_rows()
    assert set(rows) == set(pins), "calibration corpus table and canary disagree on repos"
    for name, (sha, budget) in rows.items():
        assert pins[name][0].startswith(sha), f"{name}: documented sha is not the pinned sha"
        assert budget == pins[name][1], f"{name}: documented budget is not the enforced budget"


# ───────────────────────────────────────────────────────────────────
# o1js release matrix: the compatibility claim in the README
# ───────────────────────────────────────────────────────────────────

def test_release_matrix_covers_both_supported_lines():
    names = {t["name"] for t in _load(RELEASE_SNAPSHOT)["targets"]}
    assert names == {"o1js 2.15.0", "o1js 3.0.0"}


def test_no_finding_was_lost_between_2_15_and_mesa():
    """The compatibility claim: Mesa renamed nothing the scanner keys on.

    Every finding on o1js 2.15.0 must still be reported, at the same file, line
    and severity, on the Mesa release. A loss here means a rule stopped firing
    on source that did not change.
    """
    targets = {t["name"]: t for t in _load(RELEASE_SNAPSHOT)["targets"]}
    key = lambda f: (f["file"], f["line"], f["rule_id"], f["severity"])  # noqa: E731
    old = {key(f) for f in targets["o1js 2.15.0"]["findings"]}
    new = {key(f) for f in targets["o1js 3.0.0"]["findings"]}
    assert old - new == set(), "findings present on 2.15.0 disappeared on Mesa"


def test_the_only_mesa_delta_is_the_new_32_state_example():
    """Guards the README's stated delta, so it cannot drift silently."""
    targets = {t["name"]: t for t in _load(RELEASE_SNAPSHOT)["targets"]}
    key = lambda f: (f["file"], f["line"], f["rule_id"], f["severity"])  # noqa: E731
    old = {key(f) for f in targets["o1js 2.15.0"]["findings"]}
    gained = [f for f in targets["o1js 3.0.0"]["findings"] if key(f) not in old]
    assert {f["file"] for f in gained} == {MESA_ONLY_SOURCE}


def test_readme_release_matrix_table_matches_the_snapshot():
    """The README quotes per-release counts; derive them, don't trust them.

    This repo has been bitten by hand-maintained README facts before (see
    ``test_docs_consistency``). A compatibility table is the worst place for it:
    it is the evidence a reader uses to decide whether to trust the tool on
    their o1js version.
    """
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    targets = {t["name"]: t for t in _load(RELEASE_SNAPSHOT)["targets"]}

    rows = re.findall(
        r"^\|\s*(o1js [\d.]+)[^|]*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|$",
        readme,
        re.M,
    )
    assert rows, "the README no longer states a release matrix table"
    assert {name for name, *_ in rows} == set(targets), (
        "the README table and the snapshot disagree on which releases are covered"
    )
    for name, total, high, medium, low, files in rows:
        totals = targets[name]["totals"]
        assert [int(total), int(high), int(medium), int(low), int(files)] == [
            totals["findings"], totals["high"], totals["medium"], totals["low"],
            totals["files"],
        ], f"README row for {name} disagrees with the snapshot"


def test_readme_quotes_the_pinned_release_commits():
    """A short sha in the prose must be the sha the matrix actually verifies."""
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    matrix = (REPO_ROOT / "scripts" / "o1js_release_matrix.sh").read_text(encoding="utf-8")
    for target in _load(RELEASE_SNAPSHOT)["targets"]:
        short = target["commit"][:8]
        assert short in readme, f"README does not quote {target['name']} at {short}"
        assert target["commit"] in matrix, (
            f"scripts/o1js_release_matrix.sh does not pin {target['name']} at "
            f"{target['commit']}"
        )
