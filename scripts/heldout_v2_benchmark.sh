#!/usr/bin/env bash
# Run the v2 held-out o1js benchmark against its pinned commits.
#
# Sixteen cases: nine single commits and seven (vulnerable, fixed) differential
# pairs. Selection, labels and predictions are frozen in
# research/heldout-o1js-v2/manifest.json and were written before the scanner was
# run on any of this code.
#
# Fail-closed on the same terms as the v1 runner: every side of every case must
# be checked out at exactly the 40-character commit the manifest pins, and this
# script exits non-zero otherwise. There is deliberately no fallback to a
# default branch. A pair whose two sides are not the two commits the manifest
# names is not a differential; it is two arbitrary scans with a delta between
# them, and it would still print a tidy table.
#
#   ./scripts/heldout_v2_benchmark.sh                  # clone to a temp dir
#   ./scripts/heldout_v2_benchmark.sh /path/to/corpus  # reuse a checkout dir
#   ./scripts/heldout_v2_benchmark.sh /path --json-out results.json
#   ./scripts/heldout_v2_benchmark.sh /path --allow-missing
#
# HELDOUT_CLONE_BASE overrides the clone prefix (default https://github.com/).
set -euo pipefail

usage() { sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; }

CORPUS=""
ALLOW_MISSING=0
REPORT_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --allow-missing) ALLOW_MISSING=1; REPORT_ARGS+=("$1"); shift ;;
    --corpus) CORPUS="${2:?--corpus needs a directory}"; shift 2 ;;
    --json-out) REPORT_ARGS+=("$1" "${2:?--json-out needs a path}"); shift 2 ;;
    -*) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    *) if [[ -z "$CORPUS" ]]; then CORPUS="$1"; else
         echo "unexpected argument: $1" >&2; exit 2; fi; shift ;;
  esac
done

CLEANUP=0
if [[ -z "$CORPUS" ]]; then CORPUS="$(mktemp -d)"; CLEANUP=1; fi
trap '[[ "$CLEANUP" == "1" ]] && rm -rf "$CORPUS"' EXIT
mkdir -p "$CORPUS"

PYTHON="${PYTHON:-python3}"
CLONE_BASE="${HELDOUT_CLONE_BASE:-https://github.com/}"
HERE="$(cd "$(dirname "$0")" && pwd)"
MANIFEST="${HELDOUT_V2_MANIFEST:-$HERE/../research/heldout-o1js-v2/manifest.json}"

# One clone per repository; a repository appears in several cases (six of the
# pairs are audit-fix branches off one base), and the reporter checks out each
# side in turn.
mapfile -t REPOS < <(MANIFEST="$MANIFEST" "$PYTHON" -c "
import json, os, re, sys
seen = {}
for c in json.load(open(os.environ['MANIFEST']))['cases']:
    shas = [c['commit']] if c['kind'] == 'single' else [c['vulnerable_commit'], c['fixed_commit']]
    for s in shas:
        if not re.fullmatch(r'[0-9a-f]{40}', s):
            sys.exit(f\"{c['id']}: commit {s!r} is not a full 40-char sha\")
    seen.setdefault(c['repo'], []).extend(shas)
for repo, shas in seen.items():
    print(repo, ' '.join(sorted(set(shas))))
")

FAILURES=()

for entry in "${REPOS[@]}"; do
  read -r repo shas <<<"$entry"
  dir="$CORPUS/$(basename "$repo")"

  if [[ ! -d "$dir/.git" ]]; then
    rm -rf "$dir"
    # Full clone: the pairs pin commits on merged PR branches, which a shallow
    # clone of the default branch does not contain.
    if ! git clone -q "$CLONE_BASE$repo.git" "$dir"; then
      FAILURES+=("cannot clone $repo"); rm -rf "$dir"; continue
    fi
  fi

  for sha in $shas; do
    if ! git -C "$dir" cat-file -e "$sha^{commit}" 2>/dev/null; then
      git -C "$dir" fetch -q origin "$sha" 2>/dev/null || true
    fi
    git -C "$dir" cat-file -e "$sha^{commit}" 2>/dev/null || \
      FAILURES+=("$repo: pinned commit $sha is not in $dir")
  done
done

if (( ${#FAILURES[@]} > 0 )); then
  printf 'held-out v2: %s\n' "${FAILURES[@]}" >&2
  if (( ALLOW_MISSING == 0 )); then
    echo "held-out v2: ${#FAILURES[@]} problem(s); refusing to report on an unknown" \
         "corpus. Pass --allow-missing to produce an explicitly incomplete run." >&2
    exit 1
  fi
  echo "held-out v2: --allow-missing set; continuing with an INCOMPLETE corpus." >&2
fi

"$PYTHON" "$HERE/heldout_v2_report.py" --manifest "$MANIFEST" --corpus "$CORPUS" \
  ${REPORT_ARGS[@]+"${REPORT_ARGS[@]}"}
