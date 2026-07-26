# Noir calibration (o1js-scan)

## Targets

| Tree | Role |
|------|------|
| [AztecProtocol/aztec-nr](https://github.com/AztecProtocol/aztec-nr) | Framework canary — intentional `unsafe` oracle hints |
| [zkpassport/circuits](https://github.com/zkpassport/circuits) | Real Noir app — passport / ASN.1 / ECDSA circuits |
| noir-lang libs + [zkemail.nr](https://github.com/zkemail/zkemail.nr) | Second corpus — different idioms (see below) |

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
./scripts/noirlang_canary.sh              # clones the 8 pinned repos
```

## Second corpus — noir-lang + zkEmail (0.7.1 → 0.8.0)

aztec-nr and zkpassport pin **one** idiom set, and the 0.6→0.7 retune overfit to
it: driving those two trees to zero HIGH did not generalize. Scanning eight
further libraries with 0.7.1 produced **9 HIGH**, none of them real.

Pinned commits (also encoded in `scripts/noirlang_canary.sh`):

| Repo | Commit |
|------|--------|
| noir-lang/noir-bignum | `dacecea9` |
| noir-lang/noir_json_parser | `695b25ad` |
| noir-lang/noir_sort | `c094c77e` |
| noir-lang/noir_base64 | `4200d5ff` |
| noir-lang/noir_rsa | `9a041a0f` |
| noir-lang/noir_string_search | `deef7410` |
| zkemail/zkemail.nr | `8264758c` |
| olehmisar/nodash | `3c62c0b7` |

### Before / after

| Repo | HIGH before | HIGH after | MEDIUM before | MEDIUM after |
|------|------------:|-----------:|--------------:|-------------:|
| noir-bignum | 2 | **0** | 0 | 0 |
| noir_json_parser | 5 | **0** | 2 | 2 |
| noir_sort | 1 | **0** | 0 | 0 |
| zkemail.nr | 1 | **0** | 0 | 0 |
| noir_base64 | 0 | 0 | 0 | 0 |
| noir_rsa | 0 | 0 | 0 | 0 |
| noir_string_search | 0 | 0 | 0 | 0 |
| nodash | 0 | 0 | 0 | 0 |
| **Total** | **9** | **0** | 2 | 2 |

### Classification of all 9 baseline HIGHs

The acceptance criterion for this corpus is **not** "zero HIGH" — that measures
silence, not discrimination. It is that every HIGH has been read and classified.
All nine were read; **all nine are false positives**, in three classes:

| # | Location | Verdict | Reasoning |
|---|----------|---------|-----------|
| 1 | `noir-bignum` `src/tests/bignum_test.nr:1857` `test_sqrt_fail` | **FP** | Test code. Also genuinely constrained: `qnr_limbs` → `g` → `c` → `assert(c.is_none())`. |
| 2 | `noir-bignum` `src/tests/runtime_bignum_test.nr:147` `test_add_modulus_overflow` | **FP** | Test code (`#[test(should_fail_with=…)]`). Also constrained: `one` → `a` → `result` → `assert(result == b)`. |
| 3 | `zkemail.nr` `lib/src/tests/mod.nr:110` `test_tampered_body` | **FP** | Test code. Also constrained: `tampered_body` → `tampered_body_hash` → `assert(... != ...)`. |
| 4 | `noir_json_parser` `_comparison_tools/lt.nr:18` `lte_field_240_bit` | **FP** | `predicate` is folded into `lt_parameter`, whose sign is pinned by `lt_parameter.assert_max_bit_size::<240>()` — a *method-form* assert the old seeding could not see. |
| 5 | `noir_json_parser` `_comparison_tools/lt.nr:47` `lt_field_16_bit` | **FP** | Same idiom as #4 at `::<16>`. |
| 6 | `noir_sort` `src/lib.nr:96` `sort_advanced` | **FP** | `sorted` is constrained pairwise by the `sortfn_assert(...)` callback; `\bassert` cannot match a name whose preceding char is `_`. |
| 7 | `noir_json_parser` `src/json.nr:562` `build_transcript` | **FP** | *Previously unreviewed.* `raw_transcript` → `raw` → `diff` → `assert(diff * push_transcript == 0)`. The chain was invisible because `let raw: Field = …` (type-annotated) did not parse as a `let` binding. |
| 8 | `noir_json_parser` `_string_tools/slice_packed_field.nr:608` `slice_field` | **FP** | *Previously unreviewed.* Each `chunks[i]` is bit-size asserted, and the reconstruction is checked: `assert(total == f)`. |
| 9 | `noir_json_parser` `_string_tools/slice_field.nr:66` `slice_200_bits_from_field` | **FP** | *Previously unreviewed.* `borrow` → `lo_diff`/`hi_diff` → `lo_diff.assert_max_bit_size::<200>()`, plus `assert(hi * TWO_POW_200 + lo == f)`. |

**No true positive was found in the wild on this corpus.** The Noir rule set has
still not produced a confirmed real under-constrained hint in a third-party
library. That is worth stating plainly rather than presenting the zero as a win.

### The 2 remaining noir_json_parser MEDIUMs — now classified

The acceptance criterion above says every finding is read and classified, and an
earlier revision of this document left these two as "outside the three classes
addressed here". That was the criterion not being met. Both have now been read:

| Location | Rule | Verdict | Reasoning |
|---|---|---|---|
| `noir_json_parser` `src/getters.nr` :323 (`lhs_index as u32`) | `NOIR_UNCHECKED_CAST` | **FP** | The cast is inside the body of `unconstrained fn search_for_key_in_map` (declared at :271). Unconstrained code runs **outside** the circuit as a Brillig hint — it emits no constraints, so a narrowing cast there cannot be "missing a range check"; there is no circuit to under-constrain. Soundness depends entirely on how the caller re-constrains the returned `KeySearchResult`, which is what `NOIR_UNCONSTRAINED_WITNESS` covers. |
| `noir_json_parser` `src/getters.nr` :324 (`rhs_index as u32`) | `NOIR_UNCHECKED_CAST` | **FP** | Identical mechanism, adjacent line of the same return expression. |

**Neither is a true positive**, so the Noir rule set still has no confirmed wild
true positive.

**These were a systematic FP class, not two one-offs** — and it has now been
**fixed**. `NOIR_UNCHECKED_CAST` (and any rule whose premise is "a constraint
that should exist is missing") did not check whether its enclosing function was
`unconstrained fn`, so every narrowing cast in every Brillig helper in any
codebase was a candidate.

Constraint-absence rules are now suppressed inside `unconstrained fn` bodies via
an explicit deny-list (`_UNCONSTRAINED_SUPPRESSED_RULES`), so a rule added later
defaults to **firing** there rather than being silently hidden — the safe bias
for a security tool. `NOIR_UNCONSTRAINED_INPUT` / `NOIR_UNCONSTRAINED_PUBLIC_INPUT`
are deliberately excluded: they concern `fn main`, which cannot be unconstrained.

Effect on the corpus: `noir_json_parser` MEDIUM **2 → 0**. Nothing else changed
across the ten Noir repos, and the Mina true positives are untouched.

Bounded by a paired mutation fixture (`fp_`/`tp_unconstrained_body_cast.nr`):
identical bodies, the only difference being the `unconstrained` keyword. The
tp_ twin fires, so the suppression silences Brillig bodies and not circuit code.
A unit test also pins the `[Field; N]` signature case — the `;` inside an array
type truncates a naive span walk and would silently un-suppress the body.

### Fixes in this pass

1. **Test-context suppression.** Findings from test code are dropped by default,
   detected three ways: filename (`*_test.nr`, `test_*.nr`, any `test/` or
   `tests/` path segment), a `#[test]` / `#[test(...)]` attribute, or an
   enclosing `mod test {` / `mod tests {` block (block-scoped — noir_sort has one
   at the bottom of an otherwise production file). `--include-tests` restores them.
2. **Assert family.** Constraint seeding now recognizes any call whose name
   *contains* `assert` (`assert_max_bit_size::<240>(`, `assert_lt(`,
   `sortfn_assert(`, …) including turbofish, and — for the method form
   `<receiver>.assert_xxx(...)` — seeds the **receiver** expression, not just the
   arguments. Indexed receivers reduce to their base identifier, so
   `chunks[0].assert_max_bit_size::<8>()` credits `chunks`.
3. **Type-annotated `let` bindings.** `_let_bindings` now tolerates `: Type`
   before `=`, so `let raw: Field = raw_transcript[i];` participates in the
   constraint fixpoint. This was not one of the three named classes but was
   required to explain finding #7; array types (`[Field; N]`) parse correctly
   because the annotation permits `;` only inside brackets.

### Note on the FP-1 mutation pair

`tp_bignum_test_helper.nr` does **not** use the verbatim noir-bignum
`test_sqrt_fail` body. That body is genuinely constrained (finding #1), so after
fix 3 it is silent in production too and therefore cannot discriminate the
test-suppression fix — a tp_ twin built from it would never fire. The pair keeps
the shape that matters (a test deliberately building an invalid value from a
hint) with a genuinely free hint, so the tp_ twin fires in a production path and
the fp_ twin is silent under `@scan-as src/tests/bignum_test.nr`.

### Regression delta on the first corpus

Not retuned. aztec-nr HIGH stays **0**; its MEDIUM count drops **4 → 0**, all
four being `NOIR_UNUSED_CHECK_RESULT` in `aztec/src/note/note_getter/test.nr` —
correctly removed by test-context suppression. zkpassport is unchanged (0/0).

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

Every fix in the second-corpus pass ships a **paired mutation fixture**: `fp_X.nr`
is the real code (must be silent) and `tp_X.nr` is the same code with *only* the
constraining construct removed (must fire HIGH). A fix that over-suppresses is
caught by its tp_ twin going silent. Pairs: `fp_/tp_zkemail_lte_240`,
`fp_/tp_noirsort_callback`, `fp_/tp_bignum_test_helper`.

Fixtures live under `tests/`, which the analyzer treats as test code, so the
harness analyzes each by its bare basename; `// @scan-as <path>` opts a fixture
into a test-shaped path.

## `NOIR_UNCONSTRAINED_ARRAY_INDEX` (0.11)

Added after diffing the rule set against
[NethermindEth/aztec-lint](https://github.com/NethermindEth/aztec-lint), whose
`NOIR020` ("array indexing without bounds validation") was the one
soundness-relevant rule in its catalog with no counterpart here.

### The threat model is deliberately NOT aztec-lint's

aztec-lint motivates `NOIR020` with *"unchecked indexing can cause invalid
behavior and proof failures"* — a **completeness** argument. Out-of-range
indexing in Noir makes the proof fail; a failing prover is not a soundness bug,
and this scanner does not report liveness issues.

The soundness bug in the same syntax is **selector freedom**: the implicit
bounds check establishes that the index is *in range*, never that it is the
*correct* index. Where the index picks a Merkle path position, a note, or an
allow-list entry, an unchecked index lets a malicious prover choose which
element the statement is about and still verify. That is what this rule reports,
and the description string says so.

### Suppression is a conjunction, on purpose

A finding requires that the prover's choice be unchecked in **every** way the
tool can recognise:

1. no range bound on the index (`assert(i < N)`, `assert_max_bit_size`, the
   `!= -1` found-sentinel),
2. no equality pinning the index (`==` / `assert_eq`; `!=` does **not** count —
   it excludes one value and leaves the rest free),
3. no range bound or equality on the **cast source** where the index is
   `let i = src as u32;` — Noir constrains before the cast,
4. no equality pinning the **value read back** (`let e = t[i];
   assert_eq(e, expected);`) — moving the index then breaks that assertion.

### Known recall gap, stated rather than hidden

Guard (1) is unsound as a *selector* argument: a range bound stops the prover
leaving the array, not choosing within it. It is suppressed anyway, because
without it the rule fires on essentially every dynamic index in the corpus. The
rule is therefore tuned for precision and will miss bounded-but-unpinned
selectors. `fp_array_index_bounded.nr` carries this note inline.

### Measurement — all ten pinned Noir repos

| Repo | New findings |
|---|---|
| aztec-nr | 0 |
| zkpassport/circuits | 0 |
| noir-bignum, noir_base64, noir_rsa, noir_sort, noir_string_search, nodash, zkemail.nr | 0 |
| noir_json_parser | **1** |

Pre-existing findings are unchanged everywhere (aztec-nr 0 HIGH / 0 MEDIUM,
zkpassport 0/0, zkemail.nr 6, noir-bignum 4). No HIGH budget in
`scripts/noirlang_canary.sh` moves — the rule is MEDIUM.

### Classification of the one finding

| Location | Verdict | Reasoning |
|---|---|---|
| `noir_json_parser` `src/keymap.nr` :138 (`json_entries_packed[root_index]`) | **UNREVIEWED** | `root_index` comes from `unsafe { __find_root_entry(...) }`. The circuit asserts two properties *of the selected entry* — `packed_entry.value != 0` and `entry.parent_index == 0` — but never that only one entry satisfies them. If two entries can, the prover picks the root. Whether that is reachable depends on how `json_entries_packed` is built earlier in the sort pass, which is a cross-procedure invariant a lexical tool cannot settle. Reported as a weak-predicate selector, not claimed as a bug. |

One FP was found and **fixed** during this pass rather than accepted:
`src/json.nr` :663 asserted `index.assert_max_bit_size::<8>()` on the pre-cast
value and indexed with `index as u32`. That is guard (3) above, bounded by
`fp_/tp_jsonparser_index_bitsize.nr`.

The Noir rule set still has **no confirmed wild true positive**.

### Fixtures

Three paired mutation fixtures, each `tp_` differing from its `fp_` by exactly
one deleted line: `fp_/tp_array_index` (range bound), `fp_/tp_array_index_pinned`
(equality on the read result), `fp_/tp_jsonparser_index_bitsize` (bound before
the cast). `fp_zkpassport_index_cast.nr` now also asserts this rule's absence,
so the real `!= -1` sentinel idiom guards both rules.
