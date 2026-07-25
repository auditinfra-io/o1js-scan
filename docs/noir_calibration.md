# Noir calibration (o1js-scan)

## Target

[AztecProtocol/aztec-nr](https://github.com/AztecProtocol/aztec-nr) — the
canonical Noir / Aztec framework tree with many intentional `unsafe` oracle
hints.

Pinned commit used for the 0.6→0.7 FP retune: `133806c` (local checkout under
`~/Downloads/aztec-nr` during development).

## Before / after (`NOIR_UNCONSTRAINED_WITNESS`)

| Scan | Total | HIGH unconstrained | LOW missing Safety |
|------|------:|-------------------:|-------------------:|
| Pre-tune (0.6.0 lexical) | 45 | 21 | 24 |
| Post-tune / 0.7.0 productization | ~10 | **0** | ~6 |

Reproduce:

```bash
pip install -e .
noir-scan /path/to/aztec-nr --lang noir --fail-on high --json > /tmp/aztec-nr.jsonl
# expect: zero lines with "severity": "high" for NOIR_UNCONSTRAINED_WITNESS
```

Or use the optional CI workflow / script:

```bash
./scripts/aztec_nr_canary.sh /path/to/aztec-nr
```

## What we credit as safe

- Same-file helpers that **assert** on the hint parameter (`confirm_*`, …)
- Cross-module call-site names: `constrain_*` / `confirm_*` / `verify_*` /
  `check_(non_)membership*` / `public_data_storage_read`
- Tuple `let` + asserted membership flags
- Adjacent `// Safety:` for `random()`, `avm::…`, and kernel/rollup/discovery
  deferred wording
- Split-line `let x =` / `unsafe { … }` Safety adjacency

## New inverse rules (0.7)

- `NOIR_UNUSED_CHECK_RESULT` — check/confirm/verify result discarded
- `NOIR_CONDITIONAL_CONSTRAIN` — constrain only under prover-controlled `if`
  while hint still reaches output
- Hollow same-file `confirm_*` (return-only) no longer suppresses the caller

## Corpus

Annotated fixtures live in `tests/corpus/noir/` and are exercised by
`tests/test_noir_corpus.py` on every CI run.
