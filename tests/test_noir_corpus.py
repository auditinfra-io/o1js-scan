"""Auto-discovering Noir recall / FP corpus tests.

Each ``tests/corpus/noir/*.nr`` is self-describing via annotations:

- ``// @recall-rule NOIR_…`` — expect that rule at >= ``@recall-min-severity``
- ``// @recall-rule NONE`` + ``// @recall-expect-absent RULE`` — expect RULE absent

Drop a new annotated ``.nr`` to extend coverage — no test edit required.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from o1js_scan import analyze_noir_file
from o1js_scan.vuln import Severity

_CORPUS = Path(__file__).resolve().parent / "corpus" / "noir"
_SEV_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
    "informational": 0,
}


def _annotations(text: str) -> dict:
    rule = None
    min_sev = "high"
    absent = []
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
    return {"rule": rule, "min_sev": min_sev, "absent": absent}


def _corpus_files():
    if not _CORPUS.is_dir():
        return []
    return sorted(_CORPUS.glob("*.nr"))


@pytest.mark.parametrize("path", _corpus_files(), ids=lambda p: p.name)
def test_noir_corpus_fixture(path: Path):
    src = path.read_text(encoding="utf-8")
    meta = _annotations(src)
    assert meta["rule"], f"{path.name}: missing @recall-rule"
    vulns = analyze_noir_file(str(path), src)
    rules = {v.rule_id for v in vulns}

    if meta["rule"] == "NONE":
        for rid in meta["absent"]:
            assert rid not in rules, (
                f"{path.name}: expected absent {rid}, got {[v.rule_id for v in vulns]}"
            )
        return

    hits = [v for v in vulns if v.rule_id == meta["rule"]]
    assert hits, f"{path.name}: expected {meta['rule']}, got {sorted(rules)}"
    floor = _SEV_RANK[meta["min_sev"]]
    assert any(_SEV_RANK[v.severity.value.lower()] >= floor for v in hits), (
        f"{path.name}: {meta['rule']} severity below {meta['min_sev']}: "
        f"{[v.severity.value for v in hits]}"
    )


def test_corpus_directory_is_populated():
    files = _corpus_files()
    assert len(files) >= 5, "Noir corpus should ship TP + FP fixtures"
