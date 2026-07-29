"""The three version sources must agree, and the npm manifest must be shippable.

WHY THIS EXISTS
---------------
``o1js-scan`` declares its version in three places:

    pyproject.toml      -> what PyPI publishes
    o1js_scan/__init__  -> what ``--version`` and the SARIF ``toolVersion`` report
    package.json        -> what npm publishes

Nothing kept them in step. Measured 2026-07-29, ``package.json`` said ``0.9.0``
while the other two said ``0.10.0``, so an ``npm install o1js-scan@0.9.0``
would have installed a tool whose own ``--version`` printed ``0.10.0`` — and
whose SARIF output would have stamped ``0.10.0`` into every report a consumer
archived. Version drift in a security scanner is not cosmetic: it is what a
downstream consumer uses to decide which findings a given run could produce.

The npm side had never been published at all, so the drift had no way to
surface. It would have shipped with the first ``npm publish``.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from o1js_scan import __version__

REPO_ROOT = Path(__file__).resolve().parents[1]

SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")


def _pyproject_version() -> str:
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.M)
    assert match, "no version field in pyproject.toml"
    return match.group(1)


def _package_json() -> dict:
    return json.loads((REPO_ROOT / "package.json").read_text(encoding="utf-8"))


def test_all_three_version_sources_agree():
    """pyproject / __init__ / package.json must be one number."""
    versions = {
        "pyproject.toml": _pyproject_version(),
        "o1js_scan/__init__.py": __version__,
        "package.json": _package_json()["version"],
    }
    assert len(set(versions.values())) == 1, (
        f"version drift across packaging manifests: {versions}. "
        f"A published npm package would claim a different version than the "
        f"tool reports at runtime and stamps into SARIF."
    )


def test_versions_are_plain_semver():
    """npm rejects PEP 440 suffixes (1.0.0rc1, 1.0.0.post1), so the shared
    number has to stay in the intersection of both ecosystems."""
    for name, value in (
        ("pyproject.toml", _pyproject_version()),
        ("package.json", _package_json()["version"]),
    ):
        assert SEMVER_RE.match(value), (
            f"{name} version {value!r} is not plain X.Y.Z — npm and PyPI "
            f"disagree on pre-release syntax, so keep releases to plain semver"
        )


# ───────────────────────────────────────────────────────────────────
# npm manifest shape
# ───────────────────────────────────────────────────────────────────

def test_npm_package_ships_every_python_module():
    """``files`` uses ``o1js_scan/*.py``, which does NOT recurse.

    If a subpackage is ever added, the npm tarball would silently ship an
    importable-looking package with a module missing and the wrapper would
    fail at runtime for npm users only. Fail here instead.
    """
    pkg = _package_json()
    patterns = pkg["files"]
    assert "o1js_scan/*.py" in patterns

    subpackages = [
        d for d in (REPO_ROOT / "o1js_scan").iterdir()
        if d.is_dir() and d.name != "__pycache__" and (d / "__init__.py").exists()
    ]
    assert subpackages == [], (
        f"o1js_scan has subpackage(s) {[d.name for d in subpackages]} that the "
        f"non-recursive 'o1js_scan/*.py' glob will not ship to npm — add an "
        f"explicit pattern to package.json 'files'"
    )


def test_o1js_is_an_optional_peer_dependency():
    """o1js's community-package guidance requires o1js as a peer dependency.

    It must stay **optional**: this is a static analyzer that never imports
    o1js, and it also scans Noir circuits in projects with no o1js in the tree
    at all. A hard peer dep would emit install warnings (npm>=7 auto-installs
    it) for every Noir-only user.
    """
    pkg = _package_json()
    assert "o1js" in pkg.get("peerDependencies", {}), (
        "o1js must be listed as a peer dependency for the o1js community "
        "packages list"
    )
    meta = pkg.get("peerDependenciesMeta", {}).get("o1js", {})
    assert meta.get("optional") is True, (
        "the o1js peer dep must be optional — o1js-scan never imports o1js "
        "and supports Noir-only projects"
    )


def test_declared_binaries_exist_and_are_shipped():
    pkg = _package_json()
    assert set(pkg["bin"]) == {"o1js-scan", "noir-scan"}
    for name, rel in pkg["bin"].items():
        target = REPO_ROOT / rel
        assert target.is_file(), f"bin entry {name} -> {rel} does not exist"
    assert "bin/" in pkg["files"], "bin/ is not in the published file set"


@pytest.mark.parametrize("field", ["name", "version", "license", "repository"])
def test_npm_manifest_has_registry_required_fields(field):
    assert _package_json().get(field), f"package.json missing {field!r}"
