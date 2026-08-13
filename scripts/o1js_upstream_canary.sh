#!/usr/bin/env bash
# Compatibility canary against the public o1-labs/o1js repository.
#
# This is intentionally not a finding budget: upstream tests and examples
# contain deliberately unsafe snippets. Its job is to exercise the scanner on
# current public o1js syntax and prove that every emitted JSONL record remains
# machine-readable. Detection quality is calibrated separately by mina_canary.
# Usage: o1js_upstream_canary.sh [ROOT] [OUTPUT_DIR]
# OUTPUT_DIR may instead be supplied as O1JS_CANARY_OUTPUT_DIR.
set -euo pipefail

ROOT="${1:-}"
OUTPUT_DIR="${2:-${O1JS_CANARY_OUTPUT_DIR:-}}"
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
if [[ -z "$OUTPUT_DIR" ]]; then
  OUTPUT_DIR="$(mktemp -d)"
  CLEANUP_OUTPUT=1
else
  CLEANUP_OUTPUT=0
  mkdir -p "$OUTPUT_DIR"
fi
ALL_REPORT="$OUTPUT_DIR/all-findings.jsonl"
PRODUCTION_REPORT="$OUTPUT_DIR/production-findings.jsonl"
SUMMARY="$OUTPUT_DIR/summary.txt"
trap 'if [[ "$CLEANUP_OUTPUT" == "1" ]]; then rm -rf "$OUTPUT_DIR"; fi; if [[ "$CLEANUP" == "1" ]]; then rm -rf "$(dirname "$ROOT")"; fi' EXIT

# Include tests and examples to maximize coverage of upstream API syntax. The
# gate is disabled because unsafe examples are useful scanner inputs, not
# upstream vulnerability claims.
"$PYTHON" -m o1js_scan.cli "$ROOT" \
  --lang o1js --include-tests --include-examples --fail-on none --json >"$ALL_REPORT"

# Excluding tests and examples makes this report the focused bug-hunting signal.
# Finding counts never gate this canary.
"$PYTHON" -m o1js_scan.cli "$ROOT" \
  --lang o1js --fail-on none --json >"$PRODUCTION_REPORT"

COMMIT="$(git -C "$ROOT" rev-parse HEAD)"
VERSION="$("$PYTHON" -c 'import o1js_scan; print(o1js_scan.__version__)')"
"$PYTHON" "$(dirname "$0")/o1js_upstream_report.py" \
  --all "$ALL_REPORT" --production "$PRODUCTION_REPORT" --summary "$SUMMARY" \
  --version "$VERSION" --commit "$COMMIT"
