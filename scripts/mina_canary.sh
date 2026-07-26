#!/usr/bin/env bash
# Mina / o1js canary — the o1js-side counterpart to the two Noir canaries.
#
# Until this existed the o1js rules could regress silently, which mattered more
# than for Noir: these are the rules that produced the project's only CONFIRMED
# real-world findings (marekyggdrasil/mac, iluxonchik/randomina + zkLocus).
#
# ACCEPTANCE CRITERION — deliberately NOT "zero HIGH".
# Each repo carries a BUDGET: the number of HIGH findings read and classified in
# docs/mina_calibration.md as TP / FP / UNREVIEWED. The canary fails when a repo
# goes ABOVE its budget (a new unclassified finding) *or* BELOW it (a confirmed
# true positive has been silently suppressed). Both directions are regressions.
#
# Usage:
#   ./scripts/mina_canary.sh                 # clone pinned SHAs to a temp dir
#   ./scripts/mina_canary.sh /path/to/corpus # reuse an existing checkout dir
set -euo pipefail

# repo|pinned-sha|expected HIGH (see docs/mina_calibration.md)
REPOS=(
  "marekyggdrasil/mac|83cea9cbc9cec530cc8dede356221140b7452f39|7"
  "iluxonchik/zkLocus|600f4068d37b94687cb64cf9c9dd65dcce3a2a8f|2"
  "iluxonchik/randomina|2d5781a1672f2cac43cf249ec8b63737cd854e29|1"
  "berzanorg/nacho|db85861ebbd08a06a6a52226f569829f0c5fe386|0"
  "berzanorg/xane|9002bca5640b626adb1eb2bf2df26ea8804d2d44|0"
  "o1-labs-XT/fungible-token-contract|a0d4290135ccdabcaf1defe2ea5d1a2243deb5e1|0"
  "o1-labs-XT/mastermind-zkApp|bdfc7c917f906467fd0b712661955df825d97339|0"
  "Doot-Foundation/contracts|890c9b0d281448f46bbf09d6820ab43d2b33598e|0"
  "id-Mask/smart-contracts|9b1e61124137c5515f7f3f7f3ba0d2c913f1040c|0"
  "auxo-zk/Distributed-key-generation|4d191d786c9c2337e517e72f234ff40600e20f0f|0"
  "izzetemredemir/mina-token-manager|ec91c9222fc01f383555524cbe03594aa36744dc|0"
  "45930/Voting-Playground-o1js|391ef4b8e4231602bd3d16bd9f339e5398c96436|0"
)

CORPUS="${1:-}"
CLEANUP=0
if [[ -z "$CORPUS" ]]; then
  CORPUS="$(mktemp -d)"
  CLEANUP=1
fi
trap '[[ "$CLEANUP" == "1" ]] && rm -rf "$CORPUS"' EXIT

# Drive the installed package via ``python -m`` so an older ``o1js-scan``
# earlier on PATH cannot shadow an editable checkout.
PYTHON="${PYTHON:-python3}"

FAIL=0
for entry in "${REPOS[@]}"; do
  IFS='|' read -r repo sha budget <<<"$entry"
  name="$(basename "$repo")"
  dir="$CORPUS/$name"
  if [[ ! -d "$dir" ]]; then
    if ! git clone -q "https://github.com/$repo.git" "$dir" 2>/dev/null; then
      echo "mina canary: cannot clone $repo (skip)" >&2
      continue
    fi
    git -C "$dir" checkout -q "$sha" 2>/dev/null || \
      echo "mina canary: $repo pinned SHA $sha unavailable, using default branch" >&2
  fi

  TMP="$(mktemp)"
  "$PYTHON" -m o1js_scan.cli "$dir" --lang o1js --fail-on none --json >"$TMP"
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
    printf 'FAIL %-34s HIGH=%s (budget %s) — NEW unclassified finding\n' "$name" "$HIGH" "$budget" >&2
    FAIL=1
  elif (( HIGH < budget )); then
    printf 'FAIL %-34s HIGH=%s (budget %s) — a CONFIRMED finding was LOST\n' "$name" "$HIGH" "$budget" >&2
    FAIL=1
  else
    printf 'ok   %-34s HIGH=%s\n' "$name" "$HIGH"
  fi
done

if [[ "$FAIL" != "0" ]]; then
  echo "mina canary: FAIL." >&2
  echo "  above budget -> read and classify the new finding in docs/mina_calibration.md" >&2
  echo "  below budget -> a real, disclosed finding has been suppressed; do not lower the budget" >&2
  exit 1
fi
echo "mina canary: PASS"
