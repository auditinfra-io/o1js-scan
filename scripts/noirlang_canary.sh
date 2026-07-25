#!/usr/bin/env bash
# noir-lang / zkEmail FP canary — the SECOND Noir corpus.
#
# aztec-nr and zkpassport pin one idiom set (oracle hints + confirm_/constrain_
# helpers). This canary covers different code: the official noir-lang libraries
# plus zkEmail, which lean on algebraic range-check constraints, assert-family
# calls, callback asserts, and heavy in-repo test code.
#
# ACCEPTANCE CRITERION — deliberately NOT "zero HIGH".
# Each repo carries a BUDGET: the number of HIGH findings that have been read
# and classified in docs/noir_calibration.md as TP / FP / UNREVIEWED. The canary
# fails when a repo EXCEEDS its budget, i.e. when a NEW, unclassified HIGH
# appears. Raising a budget requires classifying the finding in that doc.
#
# Usage:
#   ./scripts/noirlang_canary.sh                 # clone pinned SHAs to a temp dir
#   ./scripts/noirlang_canary.sh /path/to/corpus # reuse an existing checkout dir
set -euo pipefail

# repo|pinned-sha|HIGH budget (see docs/noir_calibration.md)
REPOS=(
  "noir-lang/noir-bignum|dacecea946237c4e2e5b7d45f318fe9a1b9dd5f5|0"
  "noir-lang/noir_json_parser|695b25add4a3229a5808ec0a0d40089c6cecfa60|0"
  "noir-lang/noir_sort|c094c77e5eebe0f5cdf72b5d9de0ff7b1def025e|0"
  "noir-lang/noir_base64|4200d5ffb1d4416f336c392ed7f3f729facbc2ad|0"
  "noir-lang/noir_rsa|9a041a0f07655237b9a2b5a3bd64ffa2c9a43e6d|0"
  "noir-lang/noir_string_search|deef74101be0ce50cb7c611cd4d126428730df59|0"
  "zkemail/zkemail.nr|8264758c6dbd6d5e29a3d58b482c3eb014424efb|0"
  "olehmisar/nodash|3c62c0b789125cdf98a96271fc20b0baa61563e4|0"
)

CORPUS="${1:-}"
CLEANUP=0
if [[ -z "$CORPUS" ]]; then
  CORPUS="$(mktemp -d)"
  CLEANUP=1
fi
trap '[[ "$CLEANUP" == "1" ]] && rm -rf "$CORPUS"' EXIT

# Drive the installed package via ``python -m`` so an older ``noir-scan``
# earlier on PATH cannot shadow an editable checkout.
PYTHON="${PYTHON:-python3}"

FAIL=0
for entry in "${REPOS[@]}"; do
  IFS='|' read -r repo sha budget <<<"$entry"
  name="$(basename "$repo")"
  dir="$CORPUS/$name"
  if [[ ! -d "$dir" ]]; then
    if ! git clone -q "https://github.com/$repo.git" "$dir" 2>/dev/null; then
      echo "noir-lang canary: cannot clone $repo (skip)" >&2
      continue
    fi
    git -C "$dir" checkout -q "$sha" 2>/dev/null || \
      echo "noir-lang canary: $repo pinned SHA $sha unavailable, using default branch" >&2
  fi

  TMP="$(mktemp)"
  "$PYTHON" -m o1js_scan.cli "$dir" --lang noir --fail-on none --json >"$TMP"
  HIGH="$("$PYTHON" -c '
import json,sys
n=0
for line in open(sys.argv[1]):
    if not line.strip(): continue
    o=json.loads(line)
    if o.get("severity")=="high":
        n+=1
        print("   ", o.get("rule_id"), o.get("file"), o.get("line"), file=sys.stderr)
print(n)
' "$TMP")"
  rm -f "$TMP"

  if (( HIGH > budget )); then
    printf 'FAIL %-24s HIGH=%s (budget %s)\n' "$name" "$HIGH" "$budget" >&2
    FAIL=1
  else
    printf 'ok   %-24s HIGH=%s (budget %s)\n' "$name" "$HIGH" "$budget"
  fi
done

if [[ "$FAIL" != "0" ]]; then
  echo "noir-lang canary: FAIL — a new HIGH appeared above its classified budget." >&2
  echo "Read each finding and classify it in docs/noir_calibration.md before raising a budget." >&2
  exit 1
fi
echo "noir-lang canary: PASS"
