"""The held-out benchmark runner must fail closed.

WHY THIS EXISTS
---------------
Before 0.19.1 the runner failed open in three places: a clone that did not
resolve was announced and skipped, a checkout of the pinned commit that did not
resolve left the repository on its default branch and carried on, and the
reporter skipped any case whose directory was absent. All three paths still
printed a tidy per-case table and exited 0.

That is the worst possible failure mode for this particular script, because its
output is recorded in research/heldout-o1js/ as evidence about the scanner. A
results file produced from five repositories, or from today's HEAD instead of
the frozen commit, is indistinguishable from a real one after the fact. So the
contract is now: scan a case only when `git rev-parse HEAD` in its checkout
equals the manifest's 40-character pin, and exit non-zero otherwise.

These tests build throwaway git repositories in a temp directory and clone over
file:// URLs, so they assert that contract without touching the network.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
REPORT = REPO_ROOT / "scripts" / "heldout_report.py"
RUNNER = REPO_ROOT / "scripts" / "heldout_benchmark.sh"

pytestmark = pytest.mark.skipif(
    shutil.which("git") is None, reason="git is required to build the fixture repos"
)

CONTRACT = """\
import { SmartContract, method, Field } from 'o1js';

export class Tiny extends SmartContract {
  @method async noop(x: Field) {
    x.assertEquals(x);
  }
}
"""


def _git(cwd: Path, *args: str) -> str:
    env = dict(
        os.environ,
        GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid",
        GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid",
        GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull,
    )
    proc = subprocess.run(
        ["git", "-C", str(cwd), *args],
        capture_output=True, text=True, env=env, check=True,
    )
    return proc.stdout.strip()


def _make_repo(root: Path, name: str) -> tuple[Path, str, str]:
    """A two-commit repo. Returns (path, first_sha, second_sha)."""
    path = root / name
    path.mkdir(parents=True)
    _git(path, "init", "-q", "-b", "main")
    (path / "contract.ts").write_text(CONTRACT, encoding="utf-8")
    _git(path, "add", "-A")
    _git(path, "commit", "-qm", "first")
    first = _git(path, "rev-parse", "HEAD")
    (path / "README.md").write_text("later\n", encoding="utf-8")
    _git(path, "add", "-A")
    _git(path, "commit", "-qm", "second")
    second = _git(path, "rev-parse", "HEAD")
    return path, first, second


def _manifest(path: Path, cases: list[dict]) -> Path:
    path.write_text(json.dumps({
        "schema": 1,
        "name": "fixture",
        "scanner_version_at_freeze": "test",
        "cases": cases,
    }, indent=2), encoding="utf-8")
    return path


def _case(case_id: str, repo: str, commit: str) -> dict:
    return {
        "id": case_id,
        "repo": repo,
        "commit": commit,
        "primary_path": "contract.ts",
        "label": "clean",
        "expected_rules": [],
        "reasoning": "fixture",
    }


def _run_report(manifest: Path, corpus: Path, *extra: str):
    return subprocess.run(
        [sys.executable, str(REPORT), "--manifest", str(manifest),
         "--corpus", str(corpus), *extra],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )


# --------------------------------------------------------------------------
# heldout_report.py -- the commit check
# --------------------------------------------------------------------------

def test_report_scans_a_case_pinned_to_its_actual_head(tmp_path):
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    _, first, second = _make_repo(corpus, "fixture-repo")
    del first
    manifest = _manifest(tmp_path / "m.json", [_case("ok", "owner/fixture-repo", second)])
    out = tmp_path / "results.json"

    proc = _run_report(manifest, corpus, "--json-out", str(out))

    assert proc.returncode == 0, proc.stderr
    results = json.loads(out.read_text(encoding="utf-8"))
    assert results["corpus_complete"] is True
    assert len(results["cases"]) == 1
    assert results["cases"][0]["expected_commit"] == second
    assert results["cases"][0]["actual_commit"] == second


def test_report_fails_when_the_checkout_is_at_a_different_commit(tmp_path):
    """The old runner's default-branch fallback landed here and said nothing."""
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    _, first, second = _make_repo(corpus, "fixture-repo")
    # Pinned to the first commit, but the checkout is left on the second.
    manifest = _manifest(tmp_path / "m.json", [_case("drift", "owner/fixture-repo", first)])
    out = tmp_path / "results.json"

    proc = _run_report(manifest, corpus, "--json-out", str(out))

    assert proc.returncode != 0
    assert first in proc.stderr and second in proc.stderr
    assert not out.exists(), "a failed verification must not leave a results file"


def test_report_fails_when_a_case_is_not_checked_out(tmp_path):
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    _, _first, second = _make_repo(corpus, "fixture-repo")
    manifest = _manifest(tmp_path / "m.json", [
        _case("present", "owner/fixture-repo", second),
        _case("absent", "owner/never-cloned", "0" * 40),
    ])

    proc = _run_report(manifest, corpus)

    assert proc.returncode != 0
    assert "absent" in proc.stderr


def test_report_fails_when_the_directory_is_not_a_git_checkout(tmp_path):
    corpus = tmp_path / "corpus"
    (corpus / "fixture-repo").mkdir(parents=True)
    (corpus / "fixture-repo" / "contract.ts").write_text(CONTRACT, encoding="utf-8")
    manifest = _manifest(tmp_path / "m.json", [_case("bare", "owner/fixture-repo", "a" * 40)])

    proc = _run_report(manifest, corpus)

    assert proc.returncode != 0
    assert "not a git checkout" in proc.stderr


def test_report_rejects_an_abbreviated_pin(tmp_path):
    """An 8-char pin cannot be compared against rev-parse output at all."""
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    _, _first, second = _make_repo(corpus, "fixture-repo")
    manifest = _manifest(tmp_path / "m.json", [_case("short", "owner/fixture-repo", second[:8])])

    proc = _run_report(manifest, corpus)

    assert proc.returncode != 0
    assert "40-character" in proc.stderr


def test_allow_missing_marks_the_run_incomplete_rather_than_hiding_it(tmp_path):
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    _, _first, second = _make_repo(corpus, "fixture-repo")
    manifest = _manifest(tmp_path / "m.json", [
        _case("present", "owner/fixture-repo", second),
        _case("absent", "owner/never-cloned", "0" * 40),
    ])
    out = tmp_path / "results.json"

    proc = _run_report(manifest, corpus, "--allow-missing", "--json-out", str(out))

    assert proc.returncode == 0, proc.stderr
    results = json.loads(out.read_text(encoding="utf-8"))
    assert results["corpus_complete"] is False
    assert [c["id"] for c in results["cases"]] == ["present"]
    assert any("absent" in s for s in results["skipped"])
    assert "INCOMPLETE" in proc.stderr


# --------------------------------------------------------------------------
# heldout_benchmark.sh -- clone and checkout, driven over file:// URLs
# --------------------------------------------------------------------------

def _run_runner(manifest: Path, corpus: Path, origins: Path, *extra: str):
    env = dict(
        os.environ,
        HELDOUT_MANIFEST=str(manifest),
        HELDOUT_CLONE_BASE=f"file://{origins}/",
        PYTHON=sys.executable,
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_CONFIG_SYSTEM=os.devnull,
    )
    return subprocess.run(
        ["bash", str(RUNNER), str(corpus), *extra],
        capture_output=True, text=True, env=env, cwd=REPO_ROOT,
    )


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash required")
def test_runner_clones_and_checks_out_the_pinned_commit(tmp_path):
    origins = tmp_path / "origins"
    _, first, _second = _make_repo(origins / "owner", "fixture-repo.git")
    manifest = _manifest(tmp_path / "m.json", [_case("ok", "owner/fixture-repo", first)])
    corpus = tmp_path / "corpus"
    out = tmp_path / "results.json"

    proc = _run_runner(manifest, corpus, origins, "--json-out", str(out))

    assert proc.returncode == 0, proc.stderr
    checked_out = _git(corpus / "fixture-repo", "rev-parse", "HEAD")
    assert checked_out == first, "the runner must land on the pin, not the default branch"
    assert json.loads(out.read_text(encoding="utf-8"))["corpus_complete"] is True


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash required")
def test_runner_fails_when_the_pinned_commit_does_not_exist(tmp_path):
    """The old runner printed 'commit unavailable' and scanned HEAD anyway."""
    origins = tmp_path / "origins"
    _, _first, second = _make_repo(origins / "owner", "fixture-repo.git")
    manifest = _manifest(tmp_path / "m.json", [_case("gone", "owner/fixture-repo", "b" * 40)])
    corpus = tmp_path / "corpus"
    out = tmp_path / "results.json"

    proc = _run_runner(manifest, corpus, origins, "--json-out", str(out))

    assert proc.returncode != 0
    assert "b" * 40 in proc.stderr
    assert not out.exists()
    # The clone is left on its default branch; the point is that nothing scanned it.
    assert _git(corpus / "fixture-repo", "rev-parse", "HEAD") == second


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash required")
def test_runner_fails_when_a_repository_cannot_be_cloned(tmp_path):
    origins = tmp_path / "origins"
    origins.mkdir()
    manifest = _manifest(tmp_path / "m.json", [_case("nope", "owner/absent-repo", "c" * 40)])
    corpus = tmp_path / "corpus"

    proc = _run_runner(manifest, corpus, origins)

    assert proc.returncode != 0
    assert "cannot clone" in proc.stderr


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash required")
def test_runner_rejects_an_abbreviated_pin_before_cloning_anything(tmp_path):
    origins = tmp_path / "origins"
    _, first, _second = _make_repo(origins / "owner", "fixture-repo.git")
    manifest = _manifest(tmp_path / "m.json", [_case("short", "owner/fixture-repo", first[:8])])
    corpus = tmp_path / "corpus"

    proc = _run_runner(manifest, corpus, origins)

    assert proc.returncode != 0
    assert not (corpus / "fixture-repo").exists()
