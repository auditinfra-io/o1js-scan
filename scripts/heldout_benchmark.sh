#!/usr/bin/env bash
# Run the held-out o1js benchmark against its pinned commits.
#
# Unlike the calibration corpus, these repositories were NOT used to design or
# tune any rule. research/heldout-o1js/manifest.json carries labels written
# before the scanner was ever run on them; this script produces the scanner's
# side of that comparison.
#
# FAIL-CLOSED BY DESIGN
# ---------------------
# Every case must be checked out at exactly the 40-character commit the
# manifest pins, and this script exits non-zero if any of them is not. There is
# deliberately no fallback to the default branch: a benchmark that quietly
# scanned today's HEAD, or quietly scanned five repositories instead of six,
# would still print a tidy table -- and that table would be measuring an
# unknown corpus while claiming to measure a frozen one. A wrong number that
# looks right is worse than no number.
#
# --allow-missing downgrades those failures to warnings, for the case where you
# knowingly want a partial run (one repository has gone away, say). The results
# it produces are marked incomplete and must not be recorded as a benchmark.
#
# Expensive (clones ~6 repositories), so it is not part of the normal test run.
#
#   ./scripts/heldout_benchmark.sh                  # clone to a temp dir
#   ./scripts/heldout_benchmark.sh /path/to/corpus  # reuse a checkout dir
#   ./scripts/heldout_benchmark.sh /path --json-out results.json
#   ./scripts/heldout_benchmark.sh /path --allow-missing
#
# HELDOUT_CLONE_BASE overrides the clone prefix (default https://github.com/),
# which is how tests/test_heldout_runner.py exercises this offline against
# local repositories.
set -euo pipefail

usage() {
  sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
}

CORPUS=""
ALLOW_MISSING=0
REPORT_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --allow-missing) ALLOW_MISSING=1; REPORT_ARGS+=("$1"); shift ;;
    --corpus) CORPUS="${2:?--corpus needs a directory}"; shift 2 ;;
    --json-out) REPORT_ARGS+=("$1" "${2:?--json-out needs a path}"); shift 2 ;;
    --) shift; REPORT_ARGS+=("$@"); break ;;
    -*) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    *)
      if [[ -z "$CORPUS" ]]; then CORPUS="$1"; else
        echo "unexpected argument: $1" >&2; exit 2
      fi
      shift ;;
  esac
done

CLEANUP=0
if [[ -z "$CORPUS" ]]; then
  CORPUS="$(mktemp -d)"; CLEANUP=1
fi
trap '[[ "$CLEANUP" == "1" ]] && rm -rf "$CORPUS"' EXIT
mkdir -p "$CORPUS"

PYTHON="${PYTHON:-python3}"
CLONE_BASE="${HELDOUT_CLONE_BASE:-https://github.com/}"
HERE="$(cd "$(dirname "$0")" && pwd)"
MANIFEST="${HELDOUT_MANIFEST:-$HERE/../research/heldout-o1js/manifest.json}"

mapfile -t REPOS < <(MANIFEST="$MANIFEST" "$PYTHON" -c "
import json, os, re, sys
cases = json.load(open(os.environ['MANIFEST']))['cases']
for c in cases:
    if not re.fullmatch(r'[0-9a-f]{40}', c['commit']):
        sys.exit(f\"{c['id']}: commit {c['commit']!r} is not a full 40-char sha\")
    print(c['id'], c['repo'], c['commit'])
")

FAILURES=()

for entry in "${REPOS[@]}"; do
  read -r id repo commit <<<"$entry"
  dir="$CORPUS/$(basename "$repo")"

  if [[ ! -d "$dir/.git" ]]; then
    rm -rf "$dir"
    # Full clone, not --depth 1: a shallow clone of the default branch usually
    # does not contain the pinned commit at all.
    if ! git clone -q "$CLONE_BASE$repo.git" "$dir"; then
      FAILURES+=("$id: cannot clone $repo")
      rm -rf "$dir"
      continue
    fi
  fi

  # The pin may be on a branch the clone did not fetch, or the checkout may be
  # a reused directory from an older manifest. Try to obtain the object before
  # concluding it is unavailable.
  if ! git -C "$dir" cat-file -e "$commit^{commit}" 2>/dev/null; then
    git -C "$dir" fetch -q origin "$commit" 2>/dev/null || true
  fi

  if ! git -C "$dir" checkout -q --detach "$commit" 2>/dev/null; then
    FAILURES+=("$id: pinned commit $commit is not in $dir")
    continue
  fi

  actual="$(git -C "$dir" rev-parse HEAD)"
  if [[ "$actual" != "$commit" ]]; then
    FAILURES+=("$id: $dir is at $actual, manifest pins $commit")
    continue
  fi
done

if (( ${#FAILURES[@]} > 0 )); then
  printf 'held-out benchmark: %s\n' "${FAILURES[@]}" >&2
  if (( ALLOW_MISSING == 0 )); then
    echo "held-out benchmark: ${#FAILURES[@]} case(s) are not at their pinned" \
         "commit; refusing to report on an unknown corpus. Pass --allow-missing" \
         "to produce an explicitly incomplete run." >&2
    exit 1
  fi
  echo "held-out benchmark: --allow-missing set; continuing with an INCOMPLETE corpus." >&2
fi

"$PYTHON" "$HERE/heldout_report.py" --manifest "$MANIFEST" --corpus "$CORPUS" ${REPORT_ARGS[@]+"${REPORT_ARGS[@]}"}
