# Held-out o1js benchmark

*Six zkApps the analyzer had never seen, labelled before it ran on them.*

---

## Why this exists

Every other evaluation in this repository has a circularity problem.
`docs/mina_calibration.md` counts findings the scanner produced on repositories
used to tune it. `research/veridise-recall/` was independent ground truth until
three rules were implemented from its findings, at which point it became a
regression corpus. Neither can answer "how does this behave on code nobody
tuned it against?"

This corpus can, once. It is frozen at o1js-scan **0.18.0**, and the labels in
`manifest.json` were written by reading the contracts and recorded **before the
scanner was run on any of them**.

## Selection

Candidates came from [`MinaFoundation/list-of-projects`](https://github.com/MinaFoundation/list-of-projects),
the ecosystem's own index, so the selection is not ours. Of 46 repositories not
already in the calibration corpus, 29 cloned and 16 contained a real
`SmartContract`. Ten of those are pre-o1js `snarkyjs`-era code and were
excluded: the analyzer documents keying on the modern `require*` and decorator
forms, so scoring it against a 2022 API measures the wrong thing.

That leaves **six cases** — the spec's minimum of ten was not reachable from
this source without including code the analyzer does not claim to support.
Criteria and the full exclusion list are in `manifest.json`.

## Running it

```bash
./scripts/heldout_benchmark.sh                    # clones the pinned commits
./scripts/heldout_benchmark.sh /path/to/corpus    # reuse a checkout
```

Results at the freeze point are in `results-0.18.0.json`.

## Results at 0.18.0

| Case | Label | Findings | Outcome |
|---|---|---:|---|
| `whisper-key-escrow` | vulnerable | 25 | flagged, HIGH |
| `usdm-token-owner` | vulnerable | 67 | flagged, HIGH — but see below |
| `mina-navi-token-election` | vulnerable | 0 | **missed** |
| `tokenizk-finance` | vulnerable | 10 | flagged, MEDIUM |
| `zeroid-mid` | vulnerable | 3 | flagged, MEDIUM |
| `repeating-life-gameoflife` | clean | 0 | correct silence |

Five of six predictions were right about *whether* the analyzer would fire. No
percentage is quoted: the denominator is six, and a recall figure over six cases
would imply a precision this evidence does not have.

### The headline is a false-positive cluster, not recall

**`usdm` produced 60 HIGH `O1JS_UNVERIFIED_PROOF` findings, and all 60 are
false positives.** `BlockProof` there is a user `Struct`, not an o1js `Proof`:

```ts
export class BlockProof extends Struct({ ... })
```

The rule matches parameter types by the `*Proof` name suffix, so twenty
`BlockProof` parameters across three methods each produce a finding — and the
contract *does* check them, folding `proof.verify(signersTree, newBlock)` into
`allValid.assertEquals(Bool(true))`. Nothing in the calibration corpus contained
a user Struct named `*Proof`, so this was invisible until now.

Sixty spurious HIGH alerts in one repository is the kind of result that gets a
security tool uninstalled. It is the most valuable thing this corpus produced,
and it is exactly what a held-out set is for.

### First real-world hit for an audit-derived rule

`tokenizk-finance` `TokeniZkPresale.ts:129` is a true positive for
`O1JS_PRECONDITION_OVERWRITTEN`:

```ts
this.network.timestamp.requireBetween(saleParams0.startTime.sub(...), UInt64.MAXINT());
// ... 10 lines of unrelated checks ...
this.network.timestamp.requireBetween(saleParams1.startTime.sub(...), UInt64.MAXINT());
```

Both windows are clearly intended; only the second is enforced. That rule came
from Veridise V-O1J-VUL-012 and had never fired outside its own fixtures.

### Two predicted misses, both confirmed

`mina-navi-token-election` produced nothing, exactly as labelled. Its two real
defects are outside what the analyzer models:

* `faucet(toAddress)` mints 50,000 tokens to any caller-supplied address with no
  authorization. No rule models mint authorization.
* `setElectionDetails()` overwrites a precondition using the legacy
  `assertEquals` spelling, which `O1JS_PRECONDITION_OVERWRITTEN` deliberately
  does not match — `assertEquals` is overwhelmingly the in-circuit `Field`
  assertion, and matching it would flood every contract with false positives.

Both were predicted in the manifest before the run. They are honest scope
limits, not surprises.

## Limitations

Read these before quoting anything above.

* **Six cases.** Small, and drawn from one index. No percentage is defensible.
* **The labels are not third-party.** They were written by the same agent that
  wrote three of the rules being evaluated. They were written before the run and
  are recorded verbatim, which rules out fitting labels to output — but it is
  weaker than independent labelling, and should be read that way.
* **One label was wrong.** `whisper-key-escrow` originally expected
  `O1JS_MISSING_STATE_PRECONDITION`; the scanner was right and the label was
  wrong (the contract does carry a precondition, in the legacy spelling). The
  correction is recorded inline in `manifest.json` rather than silently applied.
* **Two large repositories were reviewed at method-effect granularity**, not
  line by line: `tokenizk-finance` (1,864 contract lines) and `whisper-key`.
* **Findings beyond the predicted rules were not all triaged.**
  `O1JS_STALE_MERKLE_ROOT` on two cases and the `tokenizk` extras are recorded
  but unclassified. They are not counted as either true or false positives.
* **This corpus burns on use.** Fixing the `*Proof` false positive means
  developing against `usdm`, which moves that case from held-out to regression
  in the next benchmark version. That is the anti-overfitting rule, and it is
  the intended cost.
