#!/usr/bin/env bash
#
# Pack the npm tarball, install it into a scratch project, and run the real
# binaries from node_modules/.bin.
#
# This is the artifact users actually get. Running the wrapper from a repo
# checkout proves much less: the checkout has every file, while the tarball has
# only what `package.json`'s `files` globs matched. A missing module shows up
# here and nowhere else.
#
# It lives in a script rather than inline in publish.yml so that CI runs it on
# every commit. Three separate bugs shipped in the release-only version of this
# logic before it ever executed once:
#
#   * `python -m pytest` with no pytest installed  -> "No module named pytest"
#   * `npm pack --pack-destination /tmp/pkg` with no such directory
#     -> ENOENT, exit 254 (npm does NOT create the destination)
#   * both were reviewed and committed without running
#
# A release step that only runs during a release is untested code guarding a
# one-shot, irreversible action.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

pack_dir="$(mktemp -d)"
work_dir="$(mktemp -d)"
cleanup() { rm -rf "$pack_dir" "$work_dir"; }
trap cleanup EXIT

echo "==> packing from $repo_root"
npm pack --pack-destination "$pack_dir" >/dev/null

tarball="$(find "$pack_dir" -maxdepth 1 -name '*.tgz' -print -quit)"
if [ -z "$tarball" ]; then
  echo "error: npm pack produced no tarball in $pack_dir" >&2
  exit 1
fi
echo "==> packed $(basename "$tarball")"

echo "==> installing into a scratch project"
cd "$work_dir"
npm init -y >/dev/null
npm install "$tarball" >/dev/null

echo "==> running the installed binaries"
version="$(./node_modules/.bin/o1js-scan --version)"
echo "    o1js-scan --version -> $version"
./node_modules/.bin/noir-scan --help >/dev/null

# The binary must report the version the manifest claims. These are separate
# sources (package.json vs o1js_scan/__init__.py) and drifted once already:
# npm 0.9.0 shipped a tool whose --version printed 0.10.0.
expected="$(node -p "require('${repo_root}/package.json').version")"
case "$version" in
  *"$expected"*) ;;
  *)
    echo "error: installed binary reports '$version', package.json says '$expected'" >&2
    exit 1
    ;;
esac

# A real scan through the wrapper, not just --help: proves the Python modules
# the tarball shipped are importable and the analyzer actually runs.
#
# The fixture MUST produce a known finding. An "exit code is sane" check on a
# clean file passes just as happily when the analyzer is broken and silently
# finds nothing — the failure mode this whole exercise keeps running into.
cat > vuln.ts <<'EOF'
import { SmartContract, UInt64, PublicKey, method } from 'o1js';

export class VulnerableVault extends SmartContract {
  @method async withdraw(to: PublicKey, amount: UInt64) {
    this.send({ to: to, amount: amount });
  }
}
EOF
set +e
./node_modules/.bin/o1js-scan vuln.ts >scan.out 2>scan.err
scan_rc=$?
set -e
if [ "$scan_rc" -ne 1 ]; then
  echo "error: expected exit 1 (a HIGH finding), got $scan_rc" >&2
  cat scan.out scan.err >&2
  exit 1
fi
if ! grep -q "O1JS_UNCONSTRAINED_WITNESS" scan.out; then
  echo "error: the installed package did not report the expected finding" >&2
  cat scan.out scan.err >&2
  exit 1
fi
echo "    scan exit=$scan_rc, reported O1JS_UNCONSTRAINED_WITNESS as expected"

echo "==> npm package smoke test passed"
