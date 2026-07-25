# Noir calibration (o1js-scan)

## Targets

| Tree | Role |
|------|------|
| [AztecProtocol/aztec-nr](https://github.com/AztecProtocol/aztec-nr) | Framework canary — intentional `unsafe` oracle hints |
| [zkpassport/circuits](https://github.com/zkpassport/circuits) | Real Noir app — passport / ASN.1 / ECDSA circuits |

Pinned aztec-nr commit for the 0.6→0.7 FP retune: `133806c`.
ZKPassport circuits checkout used for the 0.7.x app retune: `d3a75ac`.

## Before / after

### aztec-nr (`NOIR_UNCONSTRAINED_WITNESS`)

| Scan | Total | HIGH unconstrained | LOW missing Safety |
|------|------:|-------------------:|-------------------:|
| Pre-tune (0.6.0 lexical) | 45 | 21 | 24 |
| Post-tune / 0.7.0 productization | ~10 | **0** | ~6 |

### zkpassport/circuits (app calibration)

| Scan | Total | HIGH | MEDIUM | LOW (missing Safety) |
|------|------:|-----:|-------:|---------------------:|
| Pre-tune (0.7.0 lexical) | 767 | 132 | 314 | 321 |
| Post zkpassport FP pass | 321 | **0** | **0** | 321 |

Reproduce:

```bash
pip install -e .
noir-scan /path/to/aztec-nr --lang noir --fail-on high --json > /tmp/aztec-nr.jsonl
# expect: zero HIGH

noir-scan /path/to/zkpassport-circuits --lang noir --fail-on medium --json > /tmp/zkp.jsonl
# expect: zero HIGH/MEDIUM (LOW missing-Safety hygiene may remain)
```

Or use the optional CI workflow / script:

```bash
./scripts/aztec_nr_canary.sh /path/to/aztec-nr
```

## What we credit as safe

- Same-file helpers that **assert** on the hint parameter (`confirm_*`, …)
- Cross-module call-site names: `constrain_*` / `confirm_*` / `verify_*` /
  `check_*` (passport integrity) / `public_data_storage_read`
- Tuple `let` fixpoint for **both** unsafe hints and private `main` inputs
  (`split_array` → ECDSA verify; `nullify` → public return)
- Adjacent `// Safety:` for `random()`, `avm::…`, kernel/rollup/discovery, and
  ZKPassport deferred wording (`as checked below`, `must be correct for`,
  `checked in the … circuit`, `fully re-verified`, hash/nonce binding notes)
- `assert(index != -1)` found-sentinel before `as u32` index casts
- Dead (never-read) `unsafe` bindings — not reported as HIGH

## New inverse rules (0.7)

- `NOIR_UNUSED_CHECK_RESULT` — check/confirm/verify result discarded
- `NOIR_CONDITIONAL_CONSTRAIN` — constrain only under prover-controlled `if`
  while hint still reaches output
- Hollow same-file `confirm_*` (return-only) no longer suppresses the caller

## Corpus

Annotated fixtures live in `tests/corpus/noir/` and are exercised by
`tests/test_noir_corpus.py` on every CI run. ZKPassport-shaped FPs:
`fp_zkpassport_check_helper.nr`, `fp_zkpassport_tuple_nullify.nr`,
`fp_zkpassport_split_sig.nr`, `fp_zkpassport_index_cast.nr`.
