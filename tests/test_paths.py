"""Tests for the shared path policy (test suppression, example downgrade).

Applies to BOTH backends, so each behaviour is asserted for o1js and Noir.
"""

from __future__ import annotations

from o1js_scan import (
    ScanStats,
    Severity,
    analyze_file,
    analyze_project,
    is_example_path,
    is_test_path,
)

_VULN_TS = """
import { SmartContract, UInt64, PublicKey, method } from 'o1js';
export class C extends SmartContract {
  @method async pay(to: PublicKey, amount: UInt64) {
    this.send({ to: to, amount: amount });
  }
}
"""
_VULN_NR = """
fn main(x: Field) -> pub Field {
    let guess = unsafe { hint(x) };
    guess * x
}
"""


def _rules(v):
    return sorted(x.rule_id for x in v)


# --- classification --------------------------------------------------------

def test_is_test_path_o1js_filenames():
    for p in ("Foo.test.ts", "Foo.spec.ts", "a/Foo.test.js", "Foo.spec.tsx"):
        assert is_test_path(p), p


def test_is_test_path_noir_filenames():
    for p in ("bignum_test.nr", "src/test_helpers.nr"):
        assert is_test_path(p), p


def test_is_test_path_directories():
    for p in ("tests/Foo.ts", "test/Foo.ts", "__tests__/Foo.ts", "a/spec/Foo.nr"):
        assert is_test_path(p), p


def test_is_test_path_rejects_production():
    for p in ("src/Foo.ts", "src/latest.ts", "contracts/src/Mac.ts", "src/main.nr"):
        assert not is_test_path(p), p


def test_is_example_path():
    for p in ("src/examples/a.ts", "example/a.nr", "src/token.eg.ts"):
        assert is_example_path(p), p
    for p in ("src/Foo.ts", "src/exampled.ts"):
        assert not is_example_path(p), p


# --- suppression, both backends -------------------------------------------

def test_o1js_test_path_suppressed():
    assert analyze_file("src/Vault.test.ts", _VULN_TS) == []


def test_o1js_production_path_still_fires():
    assert "O1JS_UNCONSTRAINED_WITNESS" in _rules(analyze_file("src/Vault.ts", _VULN_TS))


def test_noir_test_path_suppressed():
    assert analyze_file("src/tests/mod.nr", _VULN_NR) == []


def test_noir_production_path_still_fires():
    assert "NOIR_UNCONSTRAINED_WITNESS" in _rules(analyze_file("src/main.nr", _VULN_NR))


def test_include_tests_restores_both():
    assert _rules(analyze_file("src/Vault.test.ts", _VULN_TS, include_tests=True))
    assert _rules(analyze_file("src/tests/mod.nr", _VULN_NR, include_tests=True))


# --- example downgrade ----------------------------------------------------

def test_example_downgraded_to_low_not_dropped():
    v = analyze_file("src/examples/Vault.ts", _VULN_TS)
    assert v, "example findings must be downgraded, never dropped"
    assert all(x.severity == Severity.LOW for x in v)
    hit = [x for x in v if x.rule_id == "O1JS_UNCONSTRAINED_WITNESS"]
    assert hit and hit[0].evidence["downgraded_from"] == "high"
    assert "example" in hit[0].description.lower()


def test_eg_filename_downgraded():
    v = analyze_file("src/token.eg.ts", _VULN_TS)
    assert v and all(x.severity == Severity.LOW for x in v)


def test_include_examples_restores_severity():
    v = analyze_file("src/examples/Vault.ts", _VULN_TS, include_examples=True)
    assert any(x.severity == Severity.HIGH for x in v)


def test_example_downgrade_does_not_gate_ci(tmp_path):
    from o1js_scan.cli import main

    d = tmp_path / "src" / "examples"
    d.mkdir(parents=True)
    (d / "Vault.ts").write_text(_VULN_TS)
    assert main([str(tmp_path)]) == 0


# --- stats / transparency (Task 5) ----------------------------------------

def test_stats_counts_skipped_and_downgraded(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "Vault.test.ts").write_text(_VULN_TS)
    (tmp_path / "src" / "Other.spec.ts").write_text(_VULN_TS)
    ex = tmp_path / "src" / "examples"
    ex.mkdir()
    (ex / "Demo.ts").write_text(_VULN_TS)

    stats = ScanStats()
    analyze_project(str(tmp_path), stats=stats)
    assert stats.skipped_test_files == 2
    assert stats.downgraded_example_findings >= 1
    note = stats.note()
    assert "skipped as test code" in note and "downgraded as examples" in note


def test_stats_note_is_none_when_nothing_affected(tmp_path):
    (tmp_path / "Vault.ts").write_text(_VULN_TS)
    stats = ScanStats()
    analyze_project(str(tmp_path), stats=stats)
    assert stats.note() is None


def test_cli_prints_skip_note_to_stderr(tmp_path, capsys):
    from o1js_scan.cli import main

    (tmp_path / "Vault.test.ts").write_text(_VULN_TS)
    main([str(tmp_path)])
    err = capsys.readouterr().err
    assert "skipped as test code" in err


def test_sarif_records_stats(tmp_path):
    from o1js_scan.sarif import to_sarif

    stats = ScanStats(skipped_test_files=3, downgraded_example_findings=2)
    doc = to_sarif([], "0.0.0", stats=stats)
    props = doc["runs"][0]["invocations"][0]["properties"]
    assert props["skippedTestFiles"] == 3
    assert props["downgradedExampleFindings"] == 2
