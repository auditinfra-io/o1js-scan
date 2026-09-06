"""The registry is the single source of truth, so it must actually be complete.

WHY THIS EXISTS
---------------
Rule metadata lived in three unsynchronised places — the detector, the README
table, and the SARIF writer — and drifted in all three directions during 0.17.0
development. Generation from ``o1js_scan/rules.py`` fixes the drift only if the
registry genuinely covers every rule the analyzer can emit, so that is what
these tests check.
"""

from __future__ import annotations

import dataclasses
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from o1js_scan.rules import BACKENDS, REGISTRY, SEVERITIES, spec_for, specs_for_backend
from o1js_scan.sarif import to_sarif
from o1js_scan.vuln import Severity, Vulnerability

REPO_ROOT = Path(__file__).resolve().parents[1]


def _emitted_rule_ids() -> set:
    """Rule ids the analyzer can actually produce."""
    src = "\n".join(
        p.read_text(encoding="utf-8") for p in (REPO_ROOT / "o1js_scan").glob("*.py")
        if p.name != "rules.py"
    )
    return set(re.findall(r"""rule_id\s*=\s*["']([A-Za-z][A-Za-z0-9_]+)["']""", src))


# ───────────────────────────────────────────────────────────────────
# Shape
# ───────────────────────────────────────────────────────────────────

def test_rule_ids_are_unique():
    assert len(REGISTRY) == sum(len(specs_for_backend(b)) for b in BACKENDS), (
        "a rule id is registered twice, or a spec has an unknown backend"
    )


@pytest.mark.parametrize("spec", sorted(REGISTRY.values(), key=lambda s: s.rule_id),
                         ids=lambda s: s.rule_id)
def test_spec_fields_are_valid(spec):
    assert spec.backend in BACKENDS
    assert spec.severities, f"{spec.rule_id} declares no severity"
    for severity in spec.severities:
        assert severity in SEVERITIES, f"{spec.rule_id}: unknown severity {severity!r}"
    ranks = [SEVERITIES.index(s) for s in spec.severities]
    assert ranks == sorted(ranks), (
        f"{spec.rule_id}: severities must run most severe first, so "
        f"default_severity is the worst case"
    )
    assert spec.title and spec.description
    assert spec.tags, f"{spec.rule_id} has no SARIF tags"


def test_specs_are_immutable():
    """A frozen spec cannot be edited at runtime, so the registry is the truth."""
    spec = next(iter(REGISTRY.values()))
    with pytest.raises(dataclasses.FrozenInstanceError):
        spec.rule_id = "MUTATED"  # type: ignore[misc]


# ───────────────────────────────────────────────────────────────────
# Completeness in both directions
# ───────────────────────────────────────────────────────────────────

def test_every_emitted_rule_is_registered():
    missing = sorted(_emitted_rule_ids() - set(REGISTRY))
    assert missing == [], (
        f"the analyzer can emit {missing}, which the registry does not describe. "
        f"A finding with no registry entry gets generic SARIF metadata and no "
        f"documentation row."
    )


def test_every_registered_rule_can_be_emitted():
    emitted = _emitted_rule_ids()
    orphans = sorted(
        rid for rid, spec in REGISTRY.items()
        if rid not in emitted and not spec.metadata_only
    )
    assert orphans == [], (
        f"the registry documents {orphans}, which no detector emits. Either "
        f"implement them or mark the spec metadata_only=True."
    )


def test_backend_split_matches_the_rule_id_prefix():
    """A NOIR_ rule filed under o1js would get the wrong SARIF tags."""
    for spec in REGISTRY.values():
        if spec.rule_id.startswith("O1JS_"):
            assert spec.backend == "o1js", spec.rule_id
        elif spec.rule_id.startswith("NOIR_"):
            assert spec.backend == "noir", spec.rule_id


# ───────────────────────────────────────────────────────────────────
# SARIF metadata is backend-correct
# ───────────────────────────────────────────────────────────────────

def _finding(rule_id: str):
    return ("circuit.ts", Vulnerability(
        pattern_name=rule_id, severity=Severity.HIGH, function="f",
        location=(1, 0), origin_tier="tier", rule_id=rule_id,
        title="per-finding title naming a method", description="per-finding text",
        evidence={},
    ))


def test_sarif_tags_are_backend_specific():
    log = to_sarif(
        [_finding("O1JS_UNCONSTRAINED_WITNESS"), _finding("NOIR_UNCONSTRAINED_WITNESS")],
        "0.0.0",
    )
    tags = {r["id"]: r["properties"]["tags"] for r in log["runs"][0]["tool"]["driver"]["rules"]}
    assert "o1js" not in tags["NOIR_UNCONSTRAINED_WITNESS"], (
        "Noir findings were tagged o1js, which mislabels them in code scanning"
    )
    assert "noir" in tags["NOIR_UNCONSTRAINED_WITNESS"]
    assert "mina" in tags["O1JS_UNCONSTRAINED_WITNESS"]


def test_sarif_rule_metadata_comes_from_the_registry_not_the_first_finding():
    """Rule objects are per-rule; using a finding's title made them scan-ordered."""
    log = to_sarif([_finding("O1JS_UNCONSTRAINED_WITNESS")], "0.0.0")
    rule = log["runs"][0]["tool"]["driver"]["rules"][0]
    spec = spec_for("O1JS_UNCONSTRAINED_WITNESS")
    assert rule["shortDescription"]["text"] == spec.title
    assert rule["fullDescription"]["text"] == spec.description
    assert "per-finding" not in json.dumps(rule)


def test_every_sarif_rule_has_a_rule_specific_help_uri():
    log = to_sarif([_finding(rid) for rid in sorted(REGISTRY)], "0.0.0")
    for rule in log["runs"][0]["tool"]["driver"]["rules"]:
        assert rule["helpUri"].endswith("#" + rule["id"].lower()), rule["id"]


def test_help_uris_resolve_to_real_anchors_in_the_generated_reference():
    doc = (REPO_ROOT / "docs" / "rules.md").read_text(encoding="utf-8")
    headings = {
        h.strip().lower() for h in re.findall(r"^### (.+)$", doc, re.M)
    }
    for spec in REGISTRY.values():
        assert spec.help_anchor in headings, (
            f"{spec.rule_id}: helpUri anchor has no heading in docs/rules.md"
        )


# ───────────────────────────────────────────────────────────────────
# Generated docs must be current
# ───────────────────────────────────────────────────────────────────

def test_generated_rule_docs_are_up_to_date():
    proc = subprocess.run(
        [sys.executable, "scripts/render_rule_docs.py", "--check"],
        cwd=REPO_ROOT, capture_output=True, text=True,
    )
    assert proc.returncode == 0, (
        f"{proc.stdout}{proc.stderr}\n"
        f"Run: python3 scripts/render_rule_docs.py"
    )
