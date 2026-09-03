#!/usr/bin/env bash
# Mina benchmark: the budget canary plus an exact snapshot comparison.
#
# scripts/mina_canary.sh enforces a HIGH *count* per repo. That catches a
# finding appearing or vanishing, but not one finding being swapped for another
# at the same severity. This runs the canary and then verifies every recorded
# finding, by rule, file, line and severity, against the committed snapshot.
#
# Usage:
#   ./scripts/mina_benchmark.sh                  # clone the pinned corpus to a temp dir
#   ./scripts/mina_benchmark.sh /path/to/corpus  # reuse an existing corpus dir
set -euo pipefail

CORPUS="${1:-}"
CLEANUP=0
if [[ -z "$CORPUS" ]]; then
  CORPUS="$(mktemp -d)"
  CLEANUP=1
fi
trap '[[ "$CLEANUP" == "1" ]] && rm -rf "$CORPUS"' EXIT
mkdir -p "$CORPUS"

PYTHON="${PYTHON:-python3}"
HERE="$(cd "$(dirname "$0")" && pwd)"

# The canary clones the pinned SHAs into $CORPUS and enforces the budgets.
bash "$HERE/mina_canary.sh" "$CORPUS"

TARGETS=()
for dir in "$CORPUS"/*/; do
  [[ -d "$dir" ]] || continue
  TARGETS+=(--target "$(basename "$dir")=$dir")
done
if [[ ${#TARGETS[@]} -eq 0 ]]; then
  echo "mina benchmark: corpus is empty, nothing verified" >&2
  exit 1
fi

echo
"$PYTHON" "$HERE/scan_snapshot.py" verify \
  "$HERE/../tests/fixtures/mina_benchmark.json" "${TARGETS[@]}"
