#!/usr/bin/env python3
"""Set the release version in every manifest at once.

The version lives in three files that must agree:

    pyproject.toml          what PyPI publishes
    o1js_scan/__init__.py   what --version reports and SARIF stamps
    package.json            what npm publishes

Cutting a git tag does **not** change any of them. On 2026-07-29 a ``v0.11.0``
release was cut without bumping, so the workflow built ``0.10.0`` artifacts and
tried to publish them under a ``0.11.0`` label: the npm job failed its
tag-vs-manifest gate, and PyPI rejected the upload as a duplicate of the real
0.10.0. Nothing shipped. This script exists so that cannot happen by hand.

Usage:

    python3 scripts/bump_version.py 0.11.0     # write
    python3 scripts/bump_version.py --check    # verify agreement, change nothing

Then commit, and only then tag:

    git commit -am "Release 0.11.0"
    git tag v0.11.0 && git push origin main --tags
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")

# (path, regex with a single capturing group around the version)
SOURCES = (
    (REPO_ROOT / "pyproject.toml", re.compile(r'^(version\s*=\s*")([^"]+)(")', re.M)),
    (REPO_ROOT / "o1js_scan" / "__init__.py", re.compile(r'^(__version__\s*=\s*")([^"]+)(")', re.M)),
    (REPO_ROOT / "package.json", re.compile(r'^(\s*"version"\s*:\s*")([^"]+)(")', re.M)),
)


def read_versions() -> dict:
    out = {}
    for path, pattern in SOURCES:
        text = path.read_text(encoding="utf-8")
        match = pattern.search(text)
        if not match:
            raise SystemExit(f"error: no version field found in {path}")
        out[str(path.relative_to(REPO_ROOT))] = match.group(2)
    return out


def check() -> int:
    versions = read_versions()
    for name, value in versions.items():
        print(f"  {name:24} {value}")
    distinct = set(versions.values())
    if len(distinct) != 1:
        print(f"\nerror: manifests disagree: {sorted(distinct)}", file=sys.stderr)
        return 1
    only = distinct.pop()
    if not SEMVER_RE.match(only):
        # npm rejects PEP 440 pre-release syntax (1.0.0rc1), so the shared
        # number has to stay in the intersection of both ecosystems.
        print(f"\nerror: {only!r} is not plain X.Y.Z", file=sys.stderr)
        return 1
    print(f"\nok: all manifests at {only}")
    return 0


def bump(new: str) -> int:
    if not SEMVER_RE.match(new):
        print(f"error: {new!r} is not plain X.Y.Z (npm rejects PEP 440 suffixes)",
              file=sys.stderr)
        return 1

    current = read_versions()
    for path, pattern in SOURCES:
        text = path.read_text(encoding="utf-8")
        updated, count = pattern.subn(rf"\g<1>{new}\g<3>", text, count=1)
        if count != 1:
            raise SystemExit(f"error: failed to rewrite version in {path}")
        path.write_text(updated, encoding="utf-8")
        rel = str(path.relative_to(REPO_ROOT))
        print(f"  {rel:24} {current[rel]} -> {new}")

    # package.json must stay valid JSON after a regex rewrite
    json.loads((REPO_ROOT / "package.json").read_text(encoding="utf-8"))

    after = set(read_versions().values())
    if after != {new}:
        raise SystemExit(f"error: post-write check failed, got {sorted(after)}")
    print(f"\nok: all manifests now at {new}")
    print(f"\nnext:\n  git commit -am 'Release {new}'\n"
          f"  git tag v{new} && git push origin main --tags")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("version", nargs="?", help="new version, e.g. 0.11.0")
    ap.add_argument("--check", action="store_true",
                    help="report the current versions and verify they agree")
    args = ap.parse_args()

    if args.check or not args.version:
        return check()
    return bump(args.version)


if __name__ == "__main__":
    raise SystemExit(main())
