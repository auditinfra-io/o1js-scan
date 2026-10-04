"""The MCP server's tool logic, tested without the MCP SDK.

``o1js_scan.mcp_tools`` builds every response the server sends; the SDK adapter
only serializes it. Testing here means the fail-closed contract is checked on
every Python the core supports — 3.8 and 3.9 included, where the SDK cannot be
installed at all. ``tests/test_mcp_server.py`` repeats the important cases over
a real stdio connection where the SDK is present.

The case this file exists for: a scan that analyzed nothing must come back as
an ERROR an agent cannot report as clean.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from o1js_scan import __version__, mcp_tools
from o1js_scan.lexer import analyze_project
from o1js_scan.paths import ScanStats
from o1js_scan.rules import BACKENDS, specs_for_backend

REPO_ROOT = Path(__file__).resolve().parents[1]
VULNERABLE = REPO_ROOT / "examples" / "vulnerable_vault.ts"
SAFE_NOIR = REPO_ROOT / "examples" / "noir_constrained.nr"
SAFE_O1JS = REPO_ROOT / "tests" / "corpus" / "o1js" / "fp_precondition_distinct_properties.ts"

ALL_RULE_COUNT = sum(len(specs_for_backend(b)) for b in BACKENDS)

# Every scan response carries these, error or not.
_REQUIRED_KEYS = {
    "status", "outcome", "interpretation", "error", "scanner", "request",
    "coverage", "rules", "gate", "findings_summary", "truncated",
    "truncation_note", "findings",
}
_COVERAGE_KEYS = {
    "status", "files_matched", "files_analyzed", "files_analyzed_by_language",
    "files_skipped", "files_not_examined", "notes",
}


def _copy(src: Path, dest_dir: Path, name: str = None) -> Path:
    """Copy outside examples/ and tests/, so neither path policy applies."""
    dest = dest_dir / (name or src.name)
    shutil.copy(src, dest)
    return dest


def _assert_shape(payload: dict) -> None:
    assert set(payload) == _REQUIRED_KEYS
    assert set(payload["coverage"]) == _COVERAGE_KEYS
    assert payload["scanner"]["version"] == __version__
    skipped = payload["coverage"]["files_skipped"]
    assert skipped["total"] == sum(v for k, v in skipped.items() if k != "total")


def _assert_not_reportable_as_clean(result: mcp_tools.ToolResult) -> None:
    """Everything an agent would key on says 'error', none of it says 'clean'."""
    p = result.payload
    assert result.is_error is True
    assert p["status"] == "error"
    assert p["outcome"] == "not_scanned"
    assert p["gate"]["result"] == "not_evaluated"
    assert p["coverage"]["status"] == "none"
    assert p["error"] and p["error"]["code"] and p["error"]["message"]
    assert p["interpretation"].startswith("ERROR:")
    assert "Do NOT describe this as a clean" in p["interpretation"]
    assert p["findings"] == []


# ───────────────────────────────────────────────────────────────────
# The four outcomes the spec names
# ───────────────────────────────────────────────────────────────────

def test_vulnerable_example_returns_findings_with_coverage(tmp_path):
    target = _copy(VULNERABLE, tmp_path)
    result = mcp_tools.scan(str(target))
    p = result.payload
    _assert_shape(p)
    assert result.is_error is False
    assert p["status"] == "ok"
    assert p["outcome"] == "patterns_matched"
    assert p["findings_summary"]["total"] == len(p["findings"]) > 0
    assert any(f["severity"] == "high" for f in p["findings"])
    assert p["gate"] == {"fail_on": "high", "result": "failed"}
    cov = p["coverage"]
    assert cov["files_matched"] == cov["files_analyzed"] == 1
    assert cov["files_analyzed_by_language"] == {"o1js": 1, "noir": 0}
    assert cov["status"] == "all_candidate_files_examined"
    assert p["rules"]["backends_run"] == ["o1js"]
    assert p["rules"]["rule_count"] == len(specs_for_backend("o1js"))
    for f in p["findings"]:
        assert set(f) >= {"file", "line", "rule_id", "severity", "title", "description"}
        assert f["file"] == "vulnerable_vault.ts"


@pytest.mark.parametrize("safe, language", [(SAFE_O1JS, "o1js"), (SAFE_NOIR, "noir")])
def test_safe_example_is_success_with_coverage_and_no_soundness_claim(tmp_path, safe, language):
    result = mcp_tools.scan(str(_copy(safe, tmp_path)))
    p = result.payload
    _assert_shape(p)
    assert result.is_error is False
    assert p["outcome"] == "no_known_patterns_matched"
    assert p["findings"] == [] and p["findings_summary"]["total"] == 0
    assert p["coverage"]["files_analyzed"] == 1
    assert p["coverage"]["files_analyzed_by_language"][language] == 1
    assert p["rules"]["backends_run"] == [language]
    assert p["rules"]["rule_ids"]
    # The no-findings result disclaims soundness in the result itself.
    assert "does NOT mean the code is sound or secure" in p["interpretation"]
    assert "never as 'secure'" in p["interpretation"]


def test_empty_directory_is_an_error_not_an_empty_success(tmp_path):
    """The important one: zero files analyzed must never read as a clean scan."""
    result = mcp_tools.scan(str(tmp_path))
    _assert_shape(result.payload)
    _assert_not_reportable_as_clean(result)
    assert result.payload["error"]["code"] == "nothing_analyzed"
    assert result.payload["error"]["message"].startswith(
        f"No o1js or Noir sources were analyzed at {tmp_path}"
    )


def test_response_builder_refuses_success_when_nothing_was_analyzed():
    """Defense in depth: even a caller that skips scan()'s check gets an error."""
    result = mcp_tools._response(
        path="/x", resolved=None, lang="auto", fail_on="high",
        stats=ScanStats(), findings=[], error=None,
    )
    _assert_not_reportable_as_clean(result)
    assert result.payload["error"]["code"] == "nothing_analyzed"


def test_nonexistent_path_is_an_error(tmp_path):
    result = mcp_tools.scan(str(tmp_path / "does-not-exist"))
    _assert_shape(result.payload)
    _assert_not_reportable_as_clean(result)
    assert result.payload["error"]["code"] == "path_not_found"
    assert result.payload["request"]["resolved_path"] is None


def test_mutation_directory_without_o1js_or_noir_sources_is_an_error(tmp_path):
    """Files exist and match the globs, but none is o1js/Noir source.

    This is the realistic version of the empty-directory case — a TypeScript
    project with no zkApp in it, or a scan pointed one directory too high — and
    the one a weaker implementation would return as "ok, 0 findings".
    """
    (tmp_path / "server.ts").write_text("export const port = 8080;\n", encoding="utf-8")
    (tmp_path / "util.js").write_text("module.exports = (a, b) => a + b;\n", encoding="utf-8")
    (tmp_path / "notes.md").write_text("# not source\n", encoding="utf-8")
    result = mcp_tools.scan(str(tmp_path))
    _assert_not_reportable_as_clean(result)
    cov = result.payload["coverage"]
    assert cov["files_matched"] == 2
    assert cov["files_analyzed"] == 0
    assert cov["files_skipped"]["not_o1js_or_noir_source"] == 2
    assert "2 file(s) matched the scan globs but none was analyzed" in (
        result.payload["error"]["message"]
    )


def test_test_only_directory_is_an_error_that_names_the_reason(tmp_path):
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    _copy(VULNERABLE, tests_dir)
    result = mcp_tools.scan(str(tmp_path))
    _assert_not_reportable_as_clean(result)
    assert result.payload["coverage"]["files_skipped"]["test_code"] == 1


def test_lang_mismatch_is_an_error(tmp_path):
    _copy(VULNERABLE, tmp_path)
    result = mcp_tools.scan(str(tmp_path), lang="noir")
    _assert_not_reportable_as_clean(result)
    assert "No Noir sources were analyzed" in result.payload["error"]["message"]


@pytest.mark.parametrize("kwargs", [{"lang": "rust"}, {"fail_on": "severe"}, {"lang": ""}])
def test_invalid_arguments_are_errors(tmp_path, kwargs):
    _copy(VULNERABLE, tmp_path)
    result = mcp_tools.scan(str(tmp_path), **kwargs)
    _assert_not_reportable_as_clean(result)
    assert result.payload["error"]["code"] == "invalid_argument"


def test_scanner_exception_is_an_error_not_a_crash(tmp_path, monkeypatch):
    _copy(VULNERABLE, tmp_path)

    def boom(*_a, **_k):
        raise RuntimeError("lexer exploded")

    monkeypatch.setattr(mcp_tools, "analyze_project", boom)
    result = mcp_tools.scan(str(tmp_path))
    _assert_not_reportable_as_clean(result)
    assert result.payload["error"]["code"] == "scan_failed"
    assert "lexer exploded" in result.payload["error"]["message"]


# ───────────────────────────────────────────────────────────────────
# Coverage reporting
# ───────────────────────────────────────────────────────────────────

def test_partial_coverage_is_flagged_in_status_and_interpretation(tmp_path):
    _copy(VULNERABLE, tmp_path)
    (tmp_path / "tests").mkdir()
    _copy(VULNERABLE, tmp_path / "tests", "skipped.ts")
    p = mcp_tools.scan(str(tmp_path)).payload
    assert p["status"] == "ok"
    assert p["coverage"]["status"] == "partial"
    assert p["coverage"]["files_not_examined"] == 1
    assert "Coverage is PARTIAL" in p["interpretation"]


def test_example_downgrades_are_visible(tmp_path):
    examples = tmp_path / "examples"
    examples.mkdir()
    _copy(VULNERABLE, examples)
    p = mcp_tools.scan(str(tmp_path)).payload
    downgraded = [f for f in p["findings"] if "downgraded_from" in f]
    assert downgraded and all(f["severity"] == "low" for f in downgraded)
    assert any("downgraded to LOW" in n for n in p["coverage"]["notes"])


def test_scan_stats_account_for_every_matched_file(tmp_path):
    """matched = analyzed + every skip reason, so no file goes unexplained."""
    _copy(VULNERABLE, tmp_path)
    _copy(SAFE_NOIR, tmp_path)
    (tmp_path / "plain.ts").write_text("export const x = 1;\n", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    _copy(VULNERABLE, tmp_path / "tests")
    stats = ScanStats()
    analyze_project(str(tmp_path), stats=stats, confine_to_root=True)
    assert stats.matched_files == (
        stats.analyzed_files + stats.skipped_test_files + stats.not_source_files
        + stats.unreadable_files + stats.outside_root_files
    )
    assert stats.analyzed_files == stats.analyzed_o1js_files + stats.analyzed_noir_files == 2


# ───────────────────────────────────────────────────────────────────
# Safety: symlinks, size, read-only
# ───────────────────────────────────────────────────────────────────

def _symlink_or_skip(link: Path, target: Path) -> None:
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available on this platform")


def test_symlink_outside_the_root_is_refused_and_counted(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = _copy(VULNERABLE, outside, "secret.ts")
    root = tmp_path / "root"
    root.mkdir()
    _copy(SAFE_O1JS, root, "Contract.ts")
    _symlink_or_skip(root / "linked.ts", secret)

    p = mcp_tools.scan(str(root)).payload
    assert p["status"] == "ok"
    assert p["coverage"]["files_skipped"]["symlink_outside_root"] == 1
    assert p["coverage"]["status"] == "partial"
    # Had the link been followed, the vulnerable source would have findings.
    assert p["findings"] == []
    assert p["coverage"]["files_analyzed"] == 1


def test_symlinked_directory_outside_the_root_is_not_traversed(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    _copy(VULNERABLE, outside)
    root = tmp_path / "root"
    root.mkdir()
    _copy(SAFE_O1JS, root, "Contract.ts")
    _symlink_or_skip(root / "vendor", outside)
    p = mcp_tools.scan(str(root)).payload
    assert p["findings"] == []
    assert p["coverage"]["files_analyzed"] == 1


def test_symlink_inside_the_root_is_followed(tmp_path):
    real = _copy(VULNERABLE, tmp_path, "Real.ts")
    _symlink_or_skip(tmp_path / "Alias.ts", real)
    p = mcp_tools.scan(str(tmp_path)).payload
    assert p["coverage"]["files_skipped"]["symlink_outside_root"] == 0
    assert p["coverage"]["files_analyzed"] == 2


def test_cli_walk_is_unchanged_when_not_confined(tmp_path):
    """confine_to_root is opt-in; the CLI's file selection must not move."""
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = _copy(VULNERABLE, outside, "secret.ts")
    root = tmp_path / "root"
    root.mkdir()
    _symlink_or_skip(root / "linked.ts", secret)
    stats = ScanStats()
    findings = analyze_project(str(root), stats=stats)
    assert stats.outside_root_files == 0
    assert findings, "the unconfined walk should read the symlinked file as before"


def test_truncation_is_explicit_and_counts_cover_everything(tmp_path, monkeypatch):
    _copy(VULNERABLE, tmp_path, "A.ts")
    _copy(VULNERABLE, tmp_path, "B.ts")
    full = mcp_tools.scan(str(tmp_path)).payload
    total = full["findings_summary"]["total"]
    assert total >= 3

    monkeypatch.setattr(mcp_tools, "MAX_FINDINGS", 2)
    p = mcp_tools.scan(str(tmp_path)).payload
    assert p["truncated"] is True
    assert len(p["findings"]) == p["findings_summary"]["returned"] == 2
    assert p["findings_summary"]["total"] == total
    assert p["findings_summary"]["by_severity"] == full["findings_summary"]["by_severity"]
    assert f"first 2 of {total} findings" in p["truncation_note"]
    # Highest severity first, so the cut never hides a HIGH behind a LOW.
    assert p["findings"][0]["severity"] == full["findings"][0]["severity"] == "high"


def test_long_descriptions_are_cut_with_a_marker(tmp_path, monkeypatch):
    monkeypatch.setattr(mcp_tools, "MAX_DESCRIPTION_CHARS", 20)
    p = mcp_tools.scan(str(_copy(VULNERABLE, tmp_path))).payload
    assert all("[truncated:" in f["description"] for f in p["findings"])


def test_scan_never_writes_into_the_scanned_tree(tmp_path):
    _copy(VULNERABLE, tmp_path)
    _copy(SAFE_NOIR, tmp_path)
    before = {p: p.stat().st_mtime_ns for p in tmp_path.rglob("*")}
    mcp_tools.scan(str(tmp_path))
    after = {p: p.stat().st_mtime_ns for p in tmp_path.rglob("*")}
    assert before == after


@pytest.mark.parametrize("module", ["mcp_tools.py", "mcp_server.py"])
def test_server_modules_have_no_write_or_execute_paths(module):
    """Read-only by construction: no file writes, no subprocesses, no eval.

    Checked on the syntax tree, so prose in docstrings does not count and an
    aliased import does not slip through.
    """
    import ast

    tree = ast.parse((REPO_ROOT / "o1js_scan" / module).read_text(encoding="utf-8"))
    bad_modules = {"subprocess", "shutil", "importlib", "ctypes", "multiprocessing", "pty"}
    bad_calls = {
        "eval", "exec", "compile", "system", "popen", "spawnv", "execv", "remove",
        "unlink", "rmtree", "rename", "replace", "write_text", "write_bytes", "mkdir",
        "touch", "chmod",
    }
    hits = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            hits += [a.name for a in node.names if a.name.split(".")[0] in bad_modules]
        elif isinstance(node, ast.ImportFrom) and node.module:
            if node.module.split(".")[0] in bad_modules:
                hits.append(node.module)
        elif isinstance(node, ast.Call):
            fn = node.func
            name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", None)
            if name in bad_calls:
                hits.append(name)
            if name == "open":
                modes = [a for a in node.args[1:2]] + [
                    k.value for k in node.keywords if k.arg == "mode"]
                for m in modes:
                    if not (isinstance(m, ast.Constant) and set(str(m.value)) <= set("rbt")):
                        hits.append("open(write mode)")
    assert hits == [], f"{module} contains {hits}"


# ───────────────────────────────────────────────────────────────────
# What the agent reads
# ───────────────────────────────────────────────────────────────────

def test_scan_description_states_what_a_clean_result_means():
    assert (
        "A clean result means no pattern these rules recognize was found. It does "
        "NOT mean the code is sound or secure. This is a lexical triage tool, not "
        "a verifier. Report findings and coverage to the user; never describe a "
        "clean scan as a security guarantee."
    ) in mcp_tools.SCAN_DESCRIPTION
    assert mcp_tools.CLEAN_RESULT_WARNING in mcp_tools.SERVER_INSTRUCTIONS


def test_list_rules_covers_the_registry():
    p = mcp_tools.list_rules().payload
    assert p["rule_count"] == len(p["rules"]) == ALL_RULE_COUNT
    assert "not checked" in p["interpretation"]


def test_explain_rule_returns_the_spec_including_limitations():
    p = mcp_tools.explain_rule("O1JS_UNCONSTRAINED_SENDER")
    assert p.is_error is False
    assert p.payload["rule_id"] == "O1JS_UNCONSTRAINED_SENDER"
    assert p.payload["limitations"]
    assert p.payload["description"]


@pytest.mark.parametrize("bad", ["NOPE", "", None])
def test_explain_unknown_rule_is_an_error(bad):
    r = mcp_tools.explain_rule(bad)
    assert r.is_error is True
    assert r.payload["error"]["code"] == "unknown_rule"


# ───────────────────────────────────────────────────────────────────
# Packaging: the core stays dependency-free
# ───────────────────────────────────────────────────────────────────

def _pyproject() -> str:
    return (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")


def test_base_package_declares_zero_runtime_dependencies():
    assert re.search(r"(?m)^dependencies\s*=\s*\[\s*\]\s*$", _pyproject()), (
        "project.dependencies must stay empty; the MCP SDK belongs in the 'mcp' extra"
    )


def test_mcp_sdk_is_only_in_the_mcp_extra():
    text = _pyproject()
    extras = re.search(r"(?ms)^\[project\.optional-dependencies\]\n(.*?)(?=^\[)", text).group(1)
    assert re.search(r"(?m)^mcp\s*=\s*\[\"mcp>=", extras), "the 'mcp' extra is missing"
    dev = re.search(r"(?m)^dev\s*=\s*\[(.*)\]", extras).group(1)
    assert "mcp" not in dev, "the dev extra must not pull in the MCP SDK"
    assert 'o1js-scan-mcp = "o1js_scan.cli:mcp_main"' in text


def test_installed_metadata_requires_nothing_outside_extras():
    try:
        from importlib.metadata import PackageNotFoundError, requires
    except ImportError:  # pragma: no cover — 3.8 has it; belt and braces
        pytest.skip("importlib.metadata unavailable")
    try:
        reqs = requires("o1js-scan") or []
    except PackageNotFoundError:
        pytest.skip("o1js-scan is not installed as a distribution")
    unconditional = [r for r in reqs if "extra ==" not in r]
    assert unconditional == [], f"runtime requirements leaked into the base install: {reqs}"


def _run(code: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True,
        cwd=str(REPO_ROOT), timeout=120,
    )


def test_base_install_imports_and_scans_without_any_third_party_module():
    """The scanner, CLI and tool logic load no MCP / pydantic code at all."""
    proc = _run(
        "import sys\n"
        "import o1js_scan, o1js_scan.cli, o1js_scan.mcp_tools\n"
        f"r = o1js_scan.mcp_tools.scan({str(VULNERABLE)!r})\n"
        "assert r.payload['status'] == 'ok', r.payload\n"
        "loaded = sorted(m for m in sys.modules if m.split('.')[0] in "
        "('mcp', 'mcp_types', 'pydantic', 'anyio', 'httpx2', 'starlette'))\n"
        "assert loaded == [], loaded\n"
        "print('ok')\n"
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "ok"


def test_importing_the_server_without_the_extra_names_the_extra():
    """Simulates the base install: `mcp` is unimportable."""
    proc = _run(
        "import sys\n"
        "sys.modules['mcp'] = None\n"
        "try:\n"
        "    import o1js_scan.mcp_server\n"
        "except ImportError as e:\n"
        "    print(type(e).__name__)\n"
        "    print(e)\n"
    )
    assert proc.returncode == 0, proc.stderr
    name, message = proc.stdout.split("\n", 1)
    assert name == "MCPExtraNotInstalled"
    assert "pip install 'o1js-scan[mcp]'" in message
    assert "No module named" not in message


def test_entry_point_without_the_extra_prints_the_install_line_and_exits_2():
    proc = _run(
        "import sys\n"
        "sys.modules['mcp'] = None\n"
        "from o1js_scan.cli import mcp_main\n"
        "sys.exit(mcp_main())\n"
    )
    assert proc.returncode == 2
    assert "pip install 'o1js-scan[mcp]'" in proc.stderr
    assert "Traceback" not in proc.stderr
    assert proc.stdout == "", "stdout belongs to the MCP protocol; nothing may print there"
