"""The README's console transcripts must be reproducible.

WHY THIS EXISTS
---------------
The README's flagship demo — the first thing a visitor to the repo sees — did
not reproduce. Measured 2026-07-29, it claimed:

    $ o1js-scan examples/vulnerable_vault.ts
    HIGH     O1JS_UNCONSTRAINED_WITNESS  ...
    LOW      O1JS_UNCONSTRAINED_RECIPIENT ...
    o1js-scan: 2 finding(s) [1 high, 1 low] ... — fails (--fail-on high)
    $ echo $?
    1

The real output was ``[2 low]``, "passes", and exit **0**: ``vulnerable_vault.ts``
lives under ``examples/``, which the path classifier deliberately downgrades so
a project's own sample code cannot fail its build. The demo triggered the
tool's own suppression. Three claims were wrong at once — the HIGH severity, the
exit code, and (in the following paragraph) that ``safe_vault.ts`` "scans clean"
when it in fact reports one LOW.

A scanner whose headline example overstates its own output is the same class of
problem as a scanner that overstates a finding. These assertions keep the
transcripts honest against the real analyzer rather than against memory.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
README = REPO_ROOT / "README.md"


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "o1js_scan.cli", *args],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )


def _readme_console_blocks() -> list[str]:
    return re.findall(r"```console\n(.*?)```", README.read_text(encoding="utf-8"), re.S)


# ───────────────────────────────────────────────────────────────────
# The two headline transcripts
# ───────────────────────────────────────────────────────────────────

def test_findings_go_to_stdout_and_the_summary_to_stderr():
    """Stream contract, pinned because the README transcript interleaves them.

    A ``console`` block shows one merged stream, so it is easy to write a test
    (or a CI pipeline) against the wrong one. Findings are the data — they go to
    stdout so ``o1js-scan ... > findings.txt`` is useful; the human summary goes
    to stderr so it does not corrupt that redirect.
    """
    proc = _run("examples/vulnerable_vault.ts", "--include-examples")
    assert "O1JS_UNCONSTRAINED_WITNESS" in proc.stdout
    assert "o1js-scan:" not in proc.stdout, "summary leaked into stdout"
    assert "o1js-scan: 2 finding(s)" in proc.stderr


def test_vulnerable_vault_demo_reproduces():
    """The advertised HIGH + non-zero exit must actually happen."""
    proc = _run("examples/vulnerable_vault.ts", "--include-examples")
    assert proc.returncode == 1, (
        f"README shows `echo $?` -> 1, got {proc.returncode}\n"
        f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    )
    assert "HIGH" in proc.stdout
    assert "O1JS_UNCONSTRAINED_WITNESS" in proc.stdout
    assert "[1 high, 1 low]" in proc.stderr
    assert "fails (--fail-on high)" in proc.stderr


def test_safe_vault_demo_reproduces():
    """The fixed contract drops the HIGH and exits 0 — but is not silent."""
    proc = _run("examples/safe_vault.ts", "--include-examples")
    assert proc.returncode == 0, f"expected exit 0, got {proc.returncode}"
    assert "HIGH" not in proc.stdout, "the 'fixed' example still reports a HIGH"
    assert "[1 low]" in proc.stderr, (
        "README documents one residual LOW on safe_vault.ts; output changed"
    )
    assert "passes (--fail-on high)" in proc.stderr


def test_examples_are_downgraded_without_the_flag():
    """The behaviour that broke the original README, pinned deliberately.

    Without ``--include-examples`` the HIGH is downgraded and the run passes.
    This is intended FP-suppression, not a bug — but it is why the README must
    pass the flag, so a change here should force the README to be revisited.
    """
    proc = _run("examples/vulnerable_vault.ts")
    assert proc.returncode == 0
    assert "HIGH" not in proc.stdout
    assert "downgraded as examples" in proc.stderr


# ───────────────────────────────────────────────────────────────────
# Transcript hygiene
# ───────────────────────────────────────────────────────────────────

def test_readme_scan_commands_pass_the_examples_flag():
    """Any README transcript scanning ``examples/`` must use the flag.

    Otherwise it documents output the reader cannot reproduce — exactly the
    original defect.
    """
    offenders = []
    for block in _readme_console_blocks():
        for line in block.splitlines():
            line = line.strip()
            if not line.startswith("$ "):
                continue
            cmd = line[2:]
            if not re.match(r"(o1js-scan|noir-scan)\b", cmd):
                continue
            if "examples/" in cmd and "--include-examples" not in cmd:
                offenders.append(cmd)
    assert offenders == [], (
        f"README scans an examples/ path without --include-examples, so the "
        f"transcript below it cannot reproduce: {offenders}"
    )


def test_readme_does_not_claim_the_fixed_example_is_silent():
    """`safe_vault.ts` reports a LOW; the README must not say 'scans clean'."""
    text = README.read_text(encoding="utf-8")
    match = re.search(r"safe_vault\.ts`?\)?\s+scans clean", text)
    assert match is None, (
        "README claims safe_vault.ts 'scans clean', but it reports 1 LOW "
        "(O1JS_UNCONSTRAINED_RECIPIENT)"
    )


@pytest.mark.parametrize("path", ["examples/vulnerable_vault.ts", "examples/safe_vault.ts"])
def test_referenced_example_files_exist(path):
    assert (REPO_ROOT / path).is_file(), f"README references missing file {path}"
