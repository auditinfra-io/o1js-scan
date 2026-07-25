"""CLI / project DX: --lang filter and skip-dir behavior."""

from __future__ import annotations

from pathlib import Path

import pytest

from o1js_scan.cli import main
from o1js_scan.lexer import analyze_project


def test_lang_noir_skips_ts(tmp_path: Path):
    (tmp_path / "x.ts").write_text(
        "@method async bad() { this.x.get(); }\n"
        "class C extends SmartContract { @state(Field) x = State();\n"
        "  @method async bad() { this.x.get(); } }\n",
        encoding="utf-8",
    )
    (tmp_path / "y.nr").write_text(
        "fn main(x: Field) -> pub Field { let z = unsafe { hint(x) }; z }\n",
        encoding="utf-8",
    )
    findings = analyze_project(str(tmp_path), lang="noir")
    assert findings
    assert all(fp.endswith(".nr") for fp, _ in findings)


def test_lang_o1js_skips_nr(tmp_path: Path):
    (tmp_path / "y.nr").write_text(
        "fn main(x: Field) -> pub Field { let z = unsafe { hint(x) }; z }\n",
        encoding="utf-8",
    )
    findings = analyze_project(str(tmp_path), lang="o1js")
    assert findings == []


def test_skips_target_directory(tmp_path: Path):
    bad = tmp_path / "target" / "debug"
    bad.mkdir(parents=True)
    (bad / "generated.nr").write_text(
        "fn main(x: Field) -> pub Field { let z = unsafe { hint(x) }; z }\n",
        encoding="utf-8",
    )
    (tmp_path / "src.nr").write_text(
        "fn main(x: pub Field) -> pub Field { assert(x != 0); x }\n",
        encoding="utf-8",
    )
    findings = analyze_project(str(tmp_path), lang="noir")
    assert findings == []


def test_cli_lang_noir_on_clean_file(tmp_path: Path, capsys):
    p = tmp_path / "ok.nr"
    p.write_text(
        "fn main(x: pub Field) -> pub Field { assert(x != 0); x }\n",
        encoding="utf-8",
    )
    rc = main([str(p), "--lang", "noir", "--fail-on", "none"])
    assert rc == 0
    err = capsys.readouterr().err
    assert "no findings" in err or "finding" in err


def test_cli_help_mentions_lang():
    with pytest.raises(SystemExit) as ei:
        main(["--help"])
    assert ei.value.code == 0
