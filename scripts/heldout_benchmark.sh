#!/usr/bin/env bash
# Run the held-out o1js benchmark against its pinned commits.
#
# Unlike the calibration corpus, these repositories were NOT used to design or
# tune any rule. research/heldout-o1js/manifest.json carries labels written
# before the scanner was ever run on them; this script produces the scanner's
# side of that comparison.
#
# Expensive (clones ~6 repositories), so it is not part of the normal test run.
#
#   ./scripts/heldout_benchmark.sh                 # clone to a temp dir
#   ./scripts/heldout_benchmark.sh /path/to/corpus # reuse a checkout dir
set -euo pipefail

CORPUS="${1:-}"
CLEANUP=0
if [[ -z "$CORPUS" ]]; then
  CORPUS="$(mktemp -d)"; CLEANUP=1
fi
trap '[[ "$CLEANUP" == "1" ]] && rm -rf "$CORPUS"' EXIT
mkdir -p "$CORPUS"

PYTHON="${PYTHON:-python3}"
HERE="$(cd "$(dirname "$0")" && pwd)"
MANIFEST="$HERE/../research/heldout-o1js/manifest.json"

mapfile -t REPOS < <("$PYTHON" -c "
import json
for c in json.load(open('$MANIFEST'))['cases']:
    print(c['id'], c['repo'], c['commit'])
")

for entry in "${REPOS[@]}"; do
  read -r id repo commit <<<"$entry"
  dir="$CORPUS/$(basename "$repo")"
  if [[ ! -d "$dir" ]]; then
    git clone -q "https://github.com/$repo.git" "$dir" 2>/dev/null || {
      echo "held-out benchmark: cannot clone $repo (skip)" >&2; continue; }
    git -C "$dir" checkout -q "$commit" 2>/dev/null || \
      echo "held-out benchmark: $repo pinned commit $commit unavailable" >&2
  fi
done

"$PYTHON" "$HERE/heldout_report.py" --manifest "$MANIFEST" --corpus "$CORPUS" "${@:2}"
