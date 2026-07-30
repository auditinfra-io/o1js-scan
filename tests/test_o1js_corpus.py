"""Auto-discovering o1js recall / FP corpus tests.

Mirrors ``tests/test_noir_corpus.py`` for the o1js backend. Each
``tests/corpus/o1js/*.ts`` is self-describing via annotations:

- ``// @recall-rule O1JS_…`` — expect that rule at >= ``@recall-min-severity``
- ``// @recall-rule NONE`` + ``// @recall-expect-absent RULE`` — expect absent
- ``// @scan-as <path>`` — analyze under this path instead of the fixture's own.
  Required here: the corpus lives under ``tests/``, which the analyzer now
  treats as test code, so every fixture must declare the path it stands for.

``tp_regression_*.ts`` fixtures pin confirmed true positives found in the wild.
They exist so a future suppression heuristic cannot silently delete a real
finding — if one of those fails, a change has killed a disclosed bug report.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from o1js_scan import analyze_file

_CORPUS = Path(__file__).resolve().parent / "corpus" / "o1js"
_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _annotations(text: str) -> dict:
    rule, min_sev, absent, scan_as = None, "high", [], None
    for line in text.splitlines():
        m = re.search(r"@recall-rule\s+(\S+)", line)
        if m:
            rule = m.group(1)
        m = re.search(r"@recall-min-severity\s+(\w+)", line, re.I)
        if m:
            min_sev = m.group(1).lower()
        m = re.search(r"@recall-expect-absent\s+(\S+)", line)
        if m:
            absent.append(m.group(1))
        m = re.search(r"@scan-as\s+(\S+)", line)
        if m:
            scan_as = m.group(1)
    return {"rule": rule, "min_sev": min_sev, "absent": absent, "scan_as": scan_as}


def _corpus_files():
    return sorted(_CORPUS.glob("*.ts")) if _CORPUS.is_dir() else []


@pytest.mark.parametrize("path", _corpus_files(), ids=lambda p: p.name)
def test_o1js_corpus_fixture(path: Path):
    src = path.read_text(encoding="utf-8")
    meta = _annotations(src)
    assert meta["rule"], f"{path.name}: missing @recall-rule"
    assert meta["scan_as"], f"{path.name}: missing @scan-as (corpus lives under tests/)"
    vulns = analyze_file(meta["scan_as"], src)
    rules = {v.rule_id for v in vulns}

    if meta["rule"] == "NONE":
        for rid in meta["absent"]:
            assert rid not in rules, (
                f"{path.name}: expected absent {rid}, got {sorted(rules)}"
            )
        return

    hits = [v for v in vulns if v.rule_id == meta["rule"]]
    assert hits, f"{path.name}: expected {meta['rule']}, got {sorted(rules)}"
    floor = _SEV_RANK[meta["min_sev"]]
    assert any(_SEV_RANK[v.severity.value.lower()] >= floor for v in hits), (
        f"{path.name}: {meta['rule']} below {meta['min_sev']}: "
        f"{[v.severity.value for v in hits]}"
    )


def test_confirmed_true_positives_are_pinned():
    """The disclosed wild findings must each keep a regression fixture."""
    names = {p.name for p in _corpus_files()}
    for required in (
        "tp_regression_mac_unasserted_bool.ts",
        "tp_regression_randomina_unverified_proof.ts",
        "tp_regression_zklocus_vacuous_assert.ts",
    ):
        assert required in names, f"missing pinned regression fixture: {required}"
