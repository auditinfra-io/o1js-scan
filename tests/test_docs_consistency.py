"""Documentation claims that a reader would act on must match the code.

WHY THIS EXISTS
---------------
An audit of the README on 2026-07-29 found three claims that had drifted from
the analyzer, all of the same shape: a fact stated once, then maintained by
hand, with nothing checking it.

* ``pytest  # 154 tests`` — the suite had grown to 257.
* ``noir-scan examples/noir_unconstrained.nr  # HIGH NOIR_UNCONSTRAINED_WITNESS``
  — the real output was LOW at exit 0, because the file lives under
  ``examples/`` and the path classifier downgrades it. The o1js example above it
  had the identical defect.
* ``_SKIP_DIR_NAMES`` in ``lexer.py`` carries the comment "Keep this list
  documented in the README" — an instruction to a human, enforced by nobody.

For a security scanner the rule tables are the worst place for this to happen:
they are how a user decides whether the tool covers a bug class they care about.
A rule documented but not implemented is a false assurance; a rule implemented
but not documented is a finding nobody can interpret when it fires.

These tests derive each claim from the source of truth instead of restating it.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
README = REPO_ROOT / "README.md"


def _readme() -> str:
    return README.read_text(encoding="utf-8")


# ───────────────────────────────────────────────────────────────────
# Rule tables ↔ implemented rules
# ───────────────────────────────────────────────────────────────────

def _documented_rule_ids() -> set:
    """Rule ids from the README's `| \\`RULE\\` | severity |` tables."""
    return set(re.findall(r"^\|\s*`([A-Za-z][A-Za-z0-9_]+)`\s*\|", _readme(), re.M))


def _implemented_rule_ids() -> set:
    """Rule ids the analyzer can actually emit."""
    src = "\n".join(
        p.read_text(encoding="utf-8") for p in (REPO_ROOT / "o1js_scan").glob("*.py")
    )
    return set(re.findall(r'rule_id\s*=\s*["\']([A-Za-z][A-Za-z0-9_]+)["\']', src))


def test_every_implemented_rule_is_documented():
    """A rule that can fire but is not in the tables cannot be triaged."""
    missing = _implemented_rule_ids() - _documented_rule_ids()
    assert missing == set(), (
        f"rules the analyzer emits but the README does not document: "
        f"{sorted(missing)}"
    )


def test_every_documented_rule_is_implemented():
    """A rule in the tables that cannot fire is a false assurance of coverage."""
    phantom = _documented_rule_ids() - _implemented_rule_ids()
    assert phantom == set(), (
        f"rules documented in the README that no code emits: {sorted(phantom)}"
    )


def test_rule_id_extraction_is_not_vacuous():
    """Guard the two assertions above against matching nothing at all."""
    documented = _documented_rule_ids()
    implemented = _implemented_rule_ids()
    assert len(documented) >= 15, f"only {len(documented)} documented ids parsed"
    assert len(implemented) >= 15, f"only {len(implemented)} implemented ids parsed"
    for known in ("O1JS_UNCONSTRAINED_WITNESS", "NOIR_UNCONSTRAINED_WITNESS"):
        assert known in documented and known in implemented


def test_supported_rules_summary_counts_match_detailed_tables():
    """The at-a-glance totals must be derived from the detailed rule tables."""
    readme = _readme()
    rows = re.findall(
        r"^\| (o1js|Noir) \| (\d+) \| (\d+) \| (\d+) \| (\d+) \|$",
        readme,
        re.M,
    )
    summary = {
        backend.lower(): tuple(map(int, counts))
        for backend, *counts in rows
    }
    assert set(summary) == {"o1js", "noir"}

    expected = {}
    for backend, heading in (("o1js", "o1js"), ("noir", "Noir")):
        section = re.search(
            rf"^## What it detects \({heading}\)(.*?)(?=^## )", readme, re.M | re.S
        )
        assert section, f"missing detailed {backend} rules section"
        severities = re.findall(
            r"^\| `(?:O1JS_|NOIR_|MissingRangeCheck)[^`]*` \| ([^|]+) \|",
            section.group(1),
            re.M,
        )
        expected[backend] = (
            len(severities),
            sum("high" in severity for severity in severities),
            sum("medium" in severity for severity in severities),
            sum("low" in severity for severity in severities),
        )

    assert summary == expected
    total = tuple(sum(expected[b][i] for b in expected) for i in range(4))
    total_match = re.search(
        r"^\| \*\*Total\*\* \| \*\*(\d+)\*\* \| \*\*(\d+)\*\* "
        r"\| \*\*(\d+)\*\* \| \*\*(\d+)\*\* \|$",
        readme,
        re.M,
    )
    assert total_match
    assert tuple(map(int, total_match.groups())) == total


# ───────────────────────────────────────────────────────────────────
# Skipped directories
# ───────────────────────────────────────────────────────────────────

def test_skipped_directories_match_the_readme():
    """``lexer.py`` asks a human to keep this in sync; check it instead."""
    from o1js_scan.lexer import _SKIP_DIR_NAMES

    match = re.search(
        r"\*\*Directories skipped when walking a tree:\*\*(.+?)\n\n",
        _readme(),
        re.S,
    )
    assert match, "README no longer documents the skipped-directory list"
    documented = set(re.findall(r"`([^`]+)`", match.group(1)))

    assert documented == set(_SKIP_DIR_NAMES), (
        f"README skipped-dirs {sorted(documented)} != code "
        f"{sorted(_SKIP_DIR_NAMES)}"
    )


# ───────────────────────────────────────────────────────────────────
# GitHub Action inputs
# ───────────────────────────────────────────────────────────────────

def test_action_inputs_match_the_readme():
    """The README lists the Action's inputs and their defaults verbatim."""
    action = yaml.safe_load((REPO_ROOT / "action.yml").read_text(encoding="utf-8"))
    declared = set(action.get("inputs", {}))

    match = re.search(r"\nInputs: (.+?)Output:", _readme(), re.S)
    assert match, "README no longer lists the Action inputs"
    # Only backticked names introducing a parenthesised description are inputs;
    # the prose also backticks their *values* (`auto`, `true`, `.`), which a
    # looser pattern picks up as phantom input names.
    documented = set(re.findall(r"`([a-z][a-z-]+)`\s*\(", match.group(1)))

    assert declared == documented, (
        f"action.yml inputs {sorted(declared)} != README {sorted(documented)}"
    )
    assert set(action.get("outputs", {})) == {"sarif-file"}


# ───────────────────────────────────────────────────────────────────
# Any stated test count must be true
# ───────────────────────────────────────────────────────────────────

def _collected_test_count() -> int:
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "--collect-only"],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    match = re.search(r"(\d+) tests? collected", proc.stdout)
    assert match, f"could not read the collected count:\n{proc.stdout[-500:]}"
    return int(match.group(1))


@pytest.mark.parametrize(
    "doc", ["README.md", "CONTRIBUTING.md", "docs/o1js_community_listing.md"]
)
def test_any_stated_test_count_is_accurate(doc):
    """Docs need not state a count — but a stated one must be true.

    The README said ``# 154 tests`` long after the suite reached 257. This does
    not force anyone to quote a number; it only makes a quoted number honest.
    """
    path = REPO_ROOT / doc
    if not path.is_file():
        pytest.skip(f"{doc} not present")
    claims = [
        int(n) for n in re.findall(r"\b(\d{2,4})\s+tests\b", path.read_text(encoding="utf-8"))
    ]
    if not claims:
        return
    actual = _collected_test_count()
    wrong = [n for n in claims if n != actual]
    assert wrong == [], (
        f"{doc} claims {wrong} test(s); the suite collects {actual}. "
        f"Either update the number or drop it."
    )


# ───────────────────────────────────────────────────────────────────
# Install instructions must not promise an unpublished artifact
# ───────────────────────────────────────────────────────────────────

def test_readme_npm_instructions_are_backed_by_a_publish_workflow():
    """The README told users to ``npm install -D o1js-scan`` for months while
    the package had never been published and no workflow could publish it.

    This cannot verify the registry from an offline test run, but it can pin
    the thing that made the claim unreachable: if the README advertises npm,
    a publish path must exist.
    """
    if "npm install" not in _readme():
        return
    publish = (REPO_ROOT / ".github" / "workflows" / "publish.yml").read_text(
        encoding="utf-8"
    )
    assert "npm publish" in publish, (
        "README advertises `npm install o1js-scan` but no workflow publishes "
        "to npm — the instruction cannot work"
    )


# ───────────────────────────────────────────────────────────────────
# README must not advertise a version or a runtime it does not ship
# ───────────────────────────────────────────────────────────────────

def _manifest_version() -> str:
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.M)
    assert match, "no version in pyproject.toml"
    return match.group(1)


def test_readme_action_examples_match_the_shipped_version():
    """A copy-pasteable `uses:` line must name the version being released.

    The README sat on `@v0.15.0` through the whole 0.16.x and 0.17.0 line, so
    anyone following it pinned a scanner two minor versions old. Deriving the
    expectation from pyproject means the next bump either updates the examples
    or fails here.
    """
    readme = _readme()
    pinned = set(re.findall(r"uses:\s*auditinfra-io/o1js-scan@v([\d.]+)", readme))
    if not pinned:
        pytest.skip("README pins no explicit Action version")
    version = _manifest_version()
    assert pinned == {version}, (
        f"README Action examples pin {sorted(pinned)} but this release is "
        f"{version}. Update the examples, or switch them to a floating tag the "
        f"repository actually maintains."
    )


def test_readme_version_comments_match_the_shipped_version():
    """The commented-out `version:` pin drifts the same way the `uses:` line does."""
    commented = set(
        re.findall(r"#\s*version:\s*([\d.]+)", _readme())
    )
    if not commented:
        return
    assert commented == {_manifest_version()}


def test_ci_tests_every_advertised_python_version():
    """Advertising a classifier the matrix never runs is an untested promise."""
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    advertised = set(
        re.findall(r'"Programming Language :: Python :: (\d+\.\d+)"', pyproject)
    )
    workflow = yaml.safe_load(
        (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    )
    tested = set()
    for job in workflow["jobs"].values():
        matrix = job.get("strategy", {}).get("matrix", {})
        tested.update(str(v) for v in matrix.get("python-version", []))
    missing = sorted(advertised - tested, key=lambda v: tuple(map(int, v.split("."))))
    assert missing == [], (
        f"pyproject advertises Python {missing} but no CI matrix runs them. "
        f"Either test them or drop the classifiers."
    )
