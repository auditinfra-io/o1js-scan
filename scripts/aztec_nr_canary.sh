#!/usr/bin/env bash
# Aztec-nr FP canary: assert zero HIGH findings on a Noir tree.
# Usage: ./scripts/aztec_nr_canary.sh [path-to-aztec-nr]
set -euo pipefail
ROOT="${1:-}"
if [[ -z "$ROOT" ]]; then
  echo "usage: $0 /path/to/aztec-nr" >&2
  exit 2
fi
if [[ ! -d "$ROOT" ]]; then
  echo "aztec-nr canary: path not found: $ROOT (skip)" >&2
  exit 0
fi
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

# Always drive the installed package via ``python -m`` so an older
# ``noir-scan`` earlier on PATH cannot shadow an editable checkout.
PYTHON="${PYTHON:-python3}"
"$PYTHON" -m o1js_scan.cli "$ROOT" --lang noir --fail-on none --json >"$TMP"

HIGH="$("$PYTHON" -c '
import json,sys
n=0
for line in open(sys.argv[1]):
    if not line.strip(): continue
    o=json.loads(line)
    if o.get("severity")=="high":
        n+=1
        print(o.get("rule_id"), o.get("file"), o.get("line"), file=sys.stderr)
print(n)
' "$TMP")"
echo "aztec-nr canary: HIGH count=$HIGH"
if [[ "$HIGH" != "0" ]]; then
  echo "FAIL: expected 0 HIGH findings on aztec-nr" >&2
  exit 1
fi
echo "PASS"
