#!/usr/bin/env bash
# Pinned o1js release-compatibility matrix.
#
# The upstream canary scans o1js at HEAD and asks only "did it still parse?".
# This asks the sharper question: does the analyzer report the *same* findings
# on two pinned o1js releases that straddle a protocol boundary?
#
#   2.15.0  last release on the pre-Mesa 2.x line
#   3.0.0   the Mesa hard-fork release
#
# Mesa's breaking changes are runtime- and protocol-level, so a finding present
# on 2.15.0 must still be present on 3.0.0. Any loss is a compatibility
# regression in the scanner, not a change upstream.
#
# Usage:
#   ./scripts/o1js_release_matrix.sh                # clone both tags to a temp dir
#   ./scripts/o1js_release_matrix.sh /path/to/dir   # reuse/populate a checkout dir
set -euo pipefail

# tag|commit — keep in sync with tests/fixtures/o1js_release_matrix.json
RELEASES=(
  "2.15.0|9620ef08db60fdbfd3953be2635691cd2b5d8f2f"
  "v3.0.0|cc18a919fe40be152afb1b603c57d74a9b2225b0"
)

ROOT="${1:-}"
CLEANUP=0
if [[ -z "$ROOT" ]]; then
  ROOT="$(mktemp -d)"
  CLEANUP=1
fi
trap '[[ "$CLEANUP" == "1" ]] && rm -rf "$ROOT"' EXIT
mkdir -p "$ROOT"

PYTHON="${PYTHON:-python3}"
HERE="$(cd "$(dirname "$0")" && pwd)"
TARGETS=()

for entry in "${RELEASES[@]}"; do
  IFS='|' read -r tag sha <<<"$entry"
  # the snapshot names releases without the tag's leading "v"
  name="o1js ${tag#v}"
  dir="$ROOT/o1js-${tag#v}"
  if [[ ! -d "$dir" ]]; then
    git clone -q --depth 1 --branch "$tag" \
      https://github.com/o1-labs/o1js.git "$dir" 2>/dev/null || {
      echo "o1js release matrix: cannot clone tag $tag" >&2
      exit 2
    }
  fi
  actual="$(git -C "$dir" rev-parse HEAD)"
  if [[ "$actual" != "$sha" ]]; then
    echo "o1js release matrix: $tag resolved to $actual, expected $sha" >&2
    exit 1
  fi
  TARGETS+=(--target "$name=$dir")
done

"$PYTHON" "$HERE/scan_snapshot.py" verify \
  "$HERE/../tests/fixtures/o1js_release_matrix.json" "${TARGETS[@]}"
