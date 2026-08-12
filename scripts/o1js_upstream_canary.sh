#!/usr/bin/env bash
# Compatibility canary against the public o1-labs/o1js repository.
#
# This is intentionally not a finding budget: upstream tests and examples
# contain deliberately unsafe snippets. Its job is to exercise the scanner on
# current public o1js syntax and prove that every emitted JSONL record remains
# machine-readable. Detection quality is calibrated separately by mina_canary.
set -euo pipefail

ROOT="${1:-}"
CLEANUP=0
if [[ -z "$ROOT" ]]; then
  ROOT="$(mktemp -d)"
  CLEANUP=1
  git clone --depth 1 https://github.com/o1-labs/o1js.git "$ROOT/o1js"
  ROOT="$ROOT/o1js"
fi
trap '[[ "$CLEANUP" == "1" ]] && rm -rf "$(dirname "$ROOT")"' EXIT

if [[ ! -d "$ROOT" ]]; then
  echo "o1js upstream canary: directory not found: $ROOT" >&2
  exit 2
fi

PYTHON="${PYTHON:-python3}"
REPORT="$(mktemp)"
trap 'rm -f "$REPORT"; if [[ "$CLEANUP" == "1" ]]; then rm -rf "$(dirname "$ROOT")"; fi' EXIT

# Include tests and examples to maximize coverage of upstream API syntax. The
# gate is disabled because unsafe examples are useful scanner inputs, not
# upstream vulnerability claims.
"$PYTHON" -m o1js_scan.cli "$ROOT" \
  --lang o1js --include-tests --include-examples --fail-on none --json >"$REPORT"

"$PYTHON" - "$REPORT" <<'PY'
import json
import sys

count = 0
with open(sys.argv[1], encoding="utf-8") as report:
    for line_number, line in enumerate(report, 1):
        if not line.strip():
            continue
        finding = json.loads(line)
        required = {"file", "rule_id", "severity", "line", "title"}
        missing = required - finding.keys()
        if missing:
            raise SystemExit(
                f"finding {line_number} is missing fields: {sorted(missing)}"
            )
        count += 1
if count == 0:
    raise SystemExit(
        "o1js upstream canary: FAIL (empty report; no upstream syntax was exercised)"
    )
print(f"o1js upstream canary: PASS ({count} finding(s), JSONL valid)")
PY
