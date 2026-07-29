"""Workflow steps must not invoke tools their job never installed.

WHY THIS EXISTS
---------------
The `publish-npm` job called ``python -m pytest tests/test_packaging.py`` with
no install step. ``actions/setup-python`` provides a bare interpreter, so on the
first release that reached it (2026-07-29, run 30444574975) the step died in
under a second:

    /opt/.../bin/python: No module named pytest
    ##[error]Process completed with exit code 1.

...and the npm publish was skipped for a third time. The step had been written,
reviewed, committed and shipped without ever executing — the same
"capability that exists but is never reached" defect the analyzer itself looks
for, in the release pipeline that ships the analyzer.

Workflow steps are the least-tested code in most repositories: they only run on
the event that triggers them, which for a publish workflow is a real release.
These checks are static, so they run on every commit instead.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = sorted((REPO_ROOT / ".github" / "workflows").glob("*.yml"))

# tool -> what counts as having installed it, searched across the job's
# earlier `run:` steps and `uses:` actions
_PROVIDERS = {
    "pytest": ("pip install", "uv pip install"),
    "ruff": ("pip install", "uv pip install"),
    "twine": ("pip install", "uv pip install"),
    "build": ("pip install", "uv pip install"),
}


def _jobs():
    for path in WORKFLOWS:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        for name, job in (data.get("jobs") or {}).items():
            yield path.name, name, job


def test_workflows_exist_and_parse():
    """Vacuity guard — the checks below are meaningless on an empty list."""
    assert WORKFLOWS, "no workflow files found"
    jobs = list(_jobs())
    assert len(jobs) >= 5, f"only parsed {len(jobs)} jobs"


@pytest.mark.parametrize("tool", sorted(_PROVIDERS))
def test_python_tools_are_installed_before_use(tool):
    """A job that runs `tool` must install it first, in that same job.

    Each job gets a fresh runner; nothing carries over from another job, so
    `needs:` does not count as having installed anything.
    """
    invoke = re.compile(rf"(^|\s|/)(python -m {tool}\b|{tool}\b)")
    offenders = []

    for wf, job_name, job in _jobs():
        installed = False
        for step in job.get("steps") or []:
            run = step.get("run") or ""
            uses = step.get("uses") or ""

            if any(p in run for p in _PROVIDERS[tool]) and tool in run:
                installed = True
            # `pip install -e ".[dev]"` pulls the whole dev extra
            if re.search(r"pip install[^\n]*\[dev\]", run):
                installed = True
            if "install" in uses and tool in uses:
                installed = True

            for line in run.splitlines():
                stripped = line.strip()
                if stripped.startswith("#") or not stripped:
                    continue
                if invoke.search(stripped) and not installed:
                    offenders.append(
                        f"{wf}::{job_name} runs {tool!r} with no prior install "
                        f"-> {stripped[:70]!r}"
                    )
                    break

    assert offenders == [], "\n".join(offenders)


def test_publish_jobs_share_the_preflight_gate():
    """Every job that uploads to a registry must depend on `preflight`.

    A publish job that skips the version gate can ship artifacts labelled with
    a version they do not contain — the v0.11.0 failure.
    """
    publish = REPO_ROOT / ".github" / "workflows" / "publish.yml"
    data = yaml.safe_load(publish.read_text(encoding="utf-8"))
    jobs = data["jobs"]
    assert "preflight" in jobs, "the preflight gate is gone"

    for name, job in jobs.items():
        if name == "preflight":
            continue
        uploads = any(
            "npm publish" in (s.get("run") or "")
            or "pypi-publish" in (s.get("uses") or "")
            for s in job.get("steps") or []
        )
        if not uploads:
            continue
        needs = job.get("needs")
        needs = [needs] if isinstance(needs, str) else (needs or [])
        assert "preflight" in needs, (
            f"job {name!r} publishes to a registry without needing preflight"
        )


def test_release_workflow_publishes_to_both_registries():
    """The README advertises pip *and* npm; a release must do both."""
    text = (REPO_ROOT / ".github" / "workflows" / "publish.yml").read_text(
        encoding="utf-8"
    )
    assert "npm publish" in text, "no npm publish step"
    assert "pypi-publish" in text, "no PyPI publish step"


def test_npm_pack_destination_is_created_before_use():
    """``npm pack --pack-destination DIR`` does not mkdir DIR.

    Without an explicit ``mkdir -p``, the pack step writes nothing and the
    following ``npm install …/*.tgz`` fails ENOENT — the 2026-07-29 blocker
    after pytest was already fixed (run 30444927525).
    """
    text = (REPO_ROOT / ".github" / "workflows" / "publish.yml").read_text(
        encoding="utf-8"
    )
    assert "--pack-destination" in text, "smoke step lost npm pack"
    # Every pack-destination must be preceded (same run block) by mkdir.
    for match in re.finditer(
        r"npm pack[^\n]*--pack-destination\s+(\S+)", text
    ):
        dest = match.group(1).strip("\"'")
        # Look backwards in the same run: script for a mkdir of that path.
        preceding = text[: match.start()]
        assert re.search(
            rf"mkdir\s+(-p\s+)?{re.escape(dest)}\b", preceding
        ), (
            f"npm pack --pack-destination {dest} has no preceding mkdir -p "
            f"{dest} in publish.yml — the tarball will not be written"
        )
