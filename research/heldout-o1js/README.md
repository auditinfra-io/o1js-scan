# Held-out o1js benchmark

*Six zkApps the analyzer had never seen, labelled before it ran on them.
Five of them are still unseen; one was spent fixing what it found.*

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

## Triage of the unpredicted findings

`results-0.19.0.json` records twelve findings the labels did not predict.
Every one was read against its source at the pinned commit and classified in
`triage-0.19.0.json`: **eight true positives, four false positives.**

`unexpected` turned out to be the wrong word for most of them. The labels were
written from one `primary_path` per case, and four of the six repositories carry
a real defect in a file the labelling never opened:

| Finding | Verdict | Why |
|---|---|---|
| `whisper-key` `issueCredential` — stale merkle root (×3 vendored copies) | true positive | Writes `witness.computeRootAndKey(hash)` to `mapRoot` without ever proving the witness matches the live tree. |
| `usdm` `Contract.update` — stale merkle root | true positive | Same shape, and the signer quorum does not cover it: `Block.hash()` is `Poseidon([commitment, height])`, so the witness is outside what signers sign. |
| `tokenizk` `setPlatfromFeeAddress` — unconstrained witness | true positive | Writes its argument to state with no in-circuit gate. The `editState: signature()` the doc comment relies on is commented out, leaving `proof()` — which this method supplies. |
| `tokenizk` `configLauchpadPlatformParams` — witness not bound | true positive | Fee params checked only `> 0` before a state write; the binding read is commented out. |
| `tokenizk` `configureSaleParams` — precondition overwritten | true positive | The second `timestamp.requireBetween` silently replaces the first. |
| `tokenizk` `scripts/check-global-slot-genesis.ts` — witness not bound | true positive, not production | Correct about the code; the file is a scratch script, and the scanner has no `scripts/` convention the way it has `test/` and `examples/`. |
| `tokenizk` `claimTokens` ×3 — witness not bound | **false positive** | See below. |
| `tokenizk` `redeem` — approve without binding | false positive | The approved update carries no update fields and no balance change, so approving it grants nothing. |

### The one false-positive class worth fixing

Three of the four false positives are the same defect in the analyzer. All three
`claimTokens` methods bind their `SaleParams` / `AirdropParams` argument to
on-chain state with the standard o1js commitment idiom:

```ts
const hash0 = saleParams.hash();
this.saleParamsHash.getAndRequireEquals().assertEquals(hash0);
```

That is a complete binding — the argument is fully determined by state. The rule
misses it because the binding runs through a *derived* expression, `params.hash()`,
and witness tracking follows plain aliases (`const q = qty`) but not derived
ones. The README's limitation list has always said so; what this corpus adds is
the price. Hash-and-compare is how o1js contracts bind a Struct to a state
commitment, so this will recur on any contract written that way.

It is deliberately not fixed in 0.19.1. Following derived expressions from a
parameter to an assertion is a real extension of witness tracking, and it needs
its own regression cases and its own held-out check — not a special case bolted
onto a documentation release.

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
* **The `unexpected` column is not a false-positive count.** All twelve
  unpredicted findings are now classified in `triage-0.19.0.json`; see the
  section above. Eight are real. Reading `unexpected` as noise would have
  been wrong in both directions.
* **This corpus burns on use, and it has.** The `*Proof` false positive was
  fixed in 0.19.0, developed against `usdm`. Under the anti-overfitting rule
  that case is now marked `development` in the manifest and must not be counted
  as unseen evidence again. **Five cases remain genuinely held out.**
  `results-0.19.0.json` records the post-fix state: `usdm` drops from 67
  findings to 7, keeping the real ones and losing all 60 false HIGHs.
