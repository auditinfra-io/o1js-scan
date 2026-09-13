"""A run that examined no files must not report a clean pass.

The CLI already refused a path that does not exist, with the reasoning:

    "Otherwise a typo'd scan target silently produces zero findings and
     exit 0 — a green CI run that scanned nothing."

That guard stopped one step short. A path that EXISTS but holds nothing
analyzable produced the same green result, and the summary line said so out
loud without being able to tell the two apart:

    o1js-scan: no findings (or no Noir / o1js sources found)     EXIT=0

Measured before this change, both of these exited 0 with that line:

  * a directory containing no o1js/Noir sources at all
  * ``--lang noir`` pointed at a real o1js project

Neither is exotic. A refactor that moves ``src/``, a ``--lang`` that does not
match the project, or one leg of a monorepo CI matrix all land here, and each
reads as "scanned clean". ``vk-guard``, the sibling tool, already draws this
line the other way: *a run that checks nothing is reported as a failure, never
as a pass.*

``ScanStats.analyzed_files`` counts files a lexer actually saw — not files the
globs matched, since a matched path that fails the is-o1js / is-Noir content
check was never examined. Zero is now exit 2, and ``--allow-empty`` is the
explicit opt-out for a directory that legitimately has no circuits.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from o1js_scan.cli import main
from o1js_scan.lexer import analyze_project
from o1js_scan.paths import ScanStats

CIRCUIT = """import { SmartContract, method, State, state, Field } from 'o1js';
export class Safe extends SmartContract {
  @state(Field) x = State<Field>();
  @method async setX(v: Field) {
    this.x.getAndRequireEquals();
    this.x.set(v);
  }
}
"""


def _project(tmp_path: Path, name: str, body: str) -> Path:
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    (src / name).write_text(body, encoding="utf-8")
    return tmp_path


# ─── the empty scan is a failure ──────────────────────────────────────────

def test_a_directory_with_no_sources_exits_2(tmp_path: Path, capsys):
    (tmp_path / "README.md").write_text("# not a circuit\n", encoding="utf-8")
    assert main([str(tmp_path)]) == 2
    err = capsys.readouterr().err
    assert "nothing to scan" in err
    assert "never as a pass" in err or "not a\nclean pass" in err or "not a clean pass" in err


def test_a_lang_mismatch_exits_2_rather_than_passing(tmp_path: Path, capsys):
    """The likeliest real-world route into this, and the most dangerous.

    `--lang noir` against an o1js project used to print "no findings" and exit
    0 — a fully green CI run that never looked at a single circuit.
    """
    _project(tmp_path, "Safe.ts", CIRCUIT)
    assert main([str(tmp_path), "--lang", "noir"]) == 2
    assert "nothing to scan" in capsys.readouterr().err


def test_the_message_says_whether_globs_matched_anything(tmp_path: Path, capsys):
    """Matched-but-not-source is a different diagnosis from matched-nothing."""
    (tmp_path / "notes.ts").write_text("export const x = 1;\n", encoding="utf-8")
    assert main([str(tmp_path)]) == 2
    err = capsys.readouterr().err
    assert "matched the scan globs but none was" in err


def test_a_missing_path_still_exits_2(tmp_path: Path, capsys):
    assert main([str(tmp_path / "nope")]) == 2
    assert "path not found" in capsys.readouterr().err


# ─── a real scan is unaffected ────────────────────────────────────────────

def test_a_real_project_still_scans_and_reports_coverage(tmp_path: Path, capsys):
    _project(tmp_path, "Safe.ts", CIRCUIT)
    code = main([str(tmp_path)])
    err = capsys.readouterr().err
    assert code == 0
    assert "of 1 file(s)" in err, "the summary states how much was examined"


def test_the_no_findings_line_no_longer_hedges(tmp_path: Path, capsys):
    """It used to read "no findings (or no sources found)" — both at once."""
    _project(tmp_path, "Plain.ts", "export class Plain extends SmartContract {}\n")
    main([str(tmp_path)])
    err = capsys.readouterr().err
    assert "or no" not in err, "the ambiguity is the bug"


# ─── the explicit opt-out ─────────────────────────────────────────────────

def test_allow_empty_turns_it_back_into_a_pass(tmp_path: Path, capsys):
    (tmp_path / "README.md").write_text("# nothing here\n", encoding="utf-8")
    assert main([str(tmp_path), "--allow-empty"]) == 0
    assert "no findings in 0" in capsys.readouterr().err


def test_allow_empty_does_not_mask_a_real_finding(tmp_path: Path):
    """The opt-out must only affect the zero-file case, never the gate."""
    _project(tmp_path, "Bad.ts", CIRCUIT)
    assert main([str(tmp_path), "--allow-empty", "--fail-on", "medium"]) == 1


# ─── the counter itself ───────────────────────────────────────────────────

def test_analyzed_files_counts_only_what_a_lexer_saw(tmp_path: Path):
    _project(tmp_path, "Safe.ts", CIRCUIT)
    (tmp_path / "src" / "plain.ts").write_text("export const n = 1;\n", encoding="utf-8")
    stats = ScanStats()
    analyze_project(str(tmp_path), stats=stats)
    assert stats.matched_files == 2, "both .ts files matched the globs"
    assert stats.analyzed_files == 1, "only one is o1js source"


def test_skipped_test_files_are_not_counted_as_analyzed(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "Safe.test.ts").write_text(CIRCUIT, encoding="utf-8")
    stats = ScanStats()
    analyze_project(str(tmp_path), stats=stats)
    assert stats.skipped_test_files == 1
    assert stats.analyzed_files == 0


def test_a_project_that_is_only_tests_fails_and_says_why(tmp_path: Path, capsys):
    """Otherwise "0 findings" reads as clean when nothing was looked at."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "Safe.test.ts").write_text(CIRCUIT, encoding="utf-8")
    assert main([str(tmp_path)]) == 2
    err = capsys.readouterr().err
    assert "skipped as test code" in err
    assert "--include-tests" in err


def test_including_those_tests_makes_the_run_real_again(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "Safe.test.ts").write_text(CIRCUIT, encoding="utf-8")
    stats = ScanStats()
    analyze_project(str(tmp_path), include_tests=True, stats=stats)
    assert stats.analyzed_files == 1
