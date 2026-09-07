# Held-out o1js benchmark, v2

_Sixteen cases from a different index, labelled before the scanner ran.
Half of them are (vulnerable, fixed) commit pairs.
It found a hole in the analyzer big enough to swallow the ecosystem's token contracts._

---

## The result, first

**o1js-scan does not analyze `extends TokenContract`.** The contract gate is one
regex — `\bclass\s+(\w+)\s+extends\s+SmartContract\b`, `o1js_scan/lexer.py:137`.
A class that extends `TokenContract`, o1js's base class for every custom-token
zkApp, matches nothing. No methods are extracted, no rule runs, and the CLI
prints `no findings`.

Eight of the sixteen cases here are affected:

| Contract | Declares | `@method`s | Findings |
|---|---|---:|---:|
| MinaFoundation's official fungible-token standard | `class FungibleToken extends TokenContract` | 11 | 0 |
| SilvanaOne NFT collection | `class Collection extends TokenContract` | 28 | 0 |
| Lumina AMM pool | `class Pool extends TokenContract` | 14 | 0 |

These are the contracts that hold money. For every one of them the tool reports
a clean bill of health.

`docs/suppression-inversion.md` opens by warning that zero findings is also what
a broken rule produces. This is that warning coming true, for a whole class of
contract, in a shipped release.

It is **not confined to this corpus**. `tokenizk-finance/packages/contracts/src/TokeniZkBasicToken.ts`
extends `TokenContract` and was therefore never analyzed in the v1 runs either.
Any past result of the form "o1js-scan found nothing here" is unreliable for a
project that issues a token.

### Why it stayed hidden until now

The calibration corpus and v1 were both selected by searching for
`extends SmartContract` — the same string the analyzer keys on. A selection
criterion that mirrors the tool's own blind spot cannot expose it. v2 selected
by npm dependency on `o1js` instead, and token contracts appeared immediately.

That is the whole argument for holding a corpus out: not that it scores the
tool, but that it is chosen by someone else's criterion.

### Fixed in 0.20.0

The gate now matches `TokenContract` as well as `SmartContract`, resolves import
aliases of either (o1js's own dex example writes
`import { TokenContract as BaseTokenContract }`), tolerates a newline between
the class name and `extends`, and falls back to comment-stripped source so a
comment inside the declaration cannot hide it.

All sixteen cases are analyzed now. `results-0.19.1.json` is kept as the record
of what the tool did before, and a test refuses to let any case go back to
scoring zero unanalyzed.

**Eight of the sixteen cases are spent.** The fix was developed from them, so
they are `development` in the manifest and must not be counted as unseen
evidence again. Eight remain held out, including
`silvana-approve-delegate-unchecked`, the one pair that was analyzed all along.

### The pair result is now earned

At 0.19.1 all seven pairs showed no delta and six of those results meant
nothing. Now every pair is analyzed and every pair still shows **no forward
delta**. The five silvana `collection.ts` pairs each produce six findings on the
vulnerable side and the same six on the fixed side — four authorization-gate
false positives, one `initialize` witness, one proof-verification false
positive. Not one is the audit's defect.

So the claim this corpus was built to test — that these rules do not model the
defect classes an application audit finds — is finally supported by evidence
rather than by an accident.

### A security fix introduced a finding

The only non-zero delta runs backwards. `silvana-oracle-approval-bypass`'s
*fixed* side has one more `O1JS_UNVERIFIED_PROOF` than the vulnerable one.

The fix adds `proof.publicInput.oracleAddress…assertTrue(…)` to `update()`.
Before it, that method never touched `proof.publicInput` — and since 0.19.0 a
`*Proof`-*named* parameter is only reported when the method reads
`publicInput`/`publicOutput` on it, the corroboration added to kill the usdm
false positives. The security fix opened the gate on its own method, and a false
positive appeared (`proof.verify(vk)` lives in the private `_update` helper).

The corroboration heuristic is not neutral: adding a legitimate constraint on a
proof's public input can make an unrelated false positive appear. That was
invisible until a corpus contained a before/after pair that crossed the
threshold.

## How this corpus was built

Selection came from **npm**, not from `MinaFoundation/list-of-projects` — v1
exhausted that index's o1js-era contracts at six cases. Five searches returned
565 distinct package names; each package's published manifest was fetched and
kept only if it declared `o1js` in `dependencies` or `peerDependencies` and its
`repository` field pointed at GitHub. That left 35 repositories, 22 with real
contracts. The filter is mechanical, so the pool can be rebuilt; the exclusions
and their reasons are in `manifest.json`.

**Labels were frozen before the scan, and git proves it.** The commit that adds
`manifest.json` contains no results. The commit that adds `results-0.19.1.json`
is its child. Every label, predicted rule, predicted false positive and stated
reason was written from reading source at the pinned commits.

### Two changes from v1, both bought with v1's mistakes

- **Scans are scoped to `scan_path`** — the exact file the label was written
  from. In v1 the label came from one file while the scan covered the whole
  repository, and eight of twelve unpredicted findings turned out to be real
  defects in files the labelling had never opened. That made the "unexpected"
  column unreadable in both directions.
- **False positives are pre-registered.** Two cases predicted, before the run,
  that `O1JS_STALE_MERKLE_ROOT` would fire and be wrong, and named the
  mechanism. Both predictions held. A false positive called in advance is much
  stronger evidence about an analyzer than one classified afterwards.

## Differential pairs

Seven cases are `(vulnerable commit, fixed commit)` pairs. Six come from
`SilvanaOne/silvana-lib`'s audit remediation series — a commit titled `audit`,
then twenty titled `fix: <vulnerability>`, five of them merged from separate
`audit-fix-N` branches off one common base, so each is a single-defect change
with nothing else different. The seventh is MinaFoundation's own flash-minting
fix in the fungible-token standard, with the rationale in the commit message.

A pair holds the repository, the author, the style and the surrounding code
fixed and changes one constraint. A delta in findings is attributable to that
constraint; a null delta is a falsifiable statement about coverage.

All seven were predicted to produce no delta, and all seven did. **Six of those
seven predictions were right for the wrong reason** — the file was never
analyzed, so the claim "no rule models this defect class" was never tested.

The one pair that ran against a recognised contract:

| Pair | Defect | Delta |
|---|---|---|
| `silvana-approve-delegate-unchecked` | `approveAddress` never asserted the NFT's `canApprove` flag | none, as predicted |

An unasserted authorization flag is invisible to the rule set. That is a real
coverage result, and it is the only one of the seven this corpus actually
earned.

`silvana-uri-symbol-permissions` remains worth naming: the collection deployed
with `setZkappUri: Permissions.none()` and `setTokenSymbol: Permissions.none()`.
`O1JS_WEAK_PERMISSIONS` matches that syntax exactly and misses it only because
those two fields are not in its field list. Adding them is a two-word change —
and, like the gate, it is not being made against the case that found it.

## Results at 0.19.1

| Case | Kind | Findings | Outcome |
|---|---|---:|---|
| `silvana-transfer-approval-bypass` | pair | 6 / 6 | no delta — earned |
| `silvana-approve-delegate-unchecked` | pair | 0 / 0 | no delta, as predicted |
| `silvana-paused-nft-mint` | pair | 6 / 6 | no delta — earned |
| `silvana-admin-mint-rebinding` | pair | 6 / 6 | no delta — earned |
| `silvana-uri-symbol-permissions` | pair | 6 / 6 | no delta — earned |
| `silvana-oracle-approval-bypass` | pair | 6 / 7 | **reverse delta** — the fix added a finding |
| `mina-fungible-token-flash-mint` | pair | 2 / 2 | no delta — earned |
| `tradecoin-pair` | single | 11 | predicted FP confirmed, + 2 unpredicted FPs |
| `zk-states-verifier` | single | 0 | correct silence |
| `lumina-pool` | single | 16 | predicted FP confirmed, + 1 real finding |
| `mina-fungible-token-head` | single | 1 | 1 FP (`setAdmin`) |
| `pinsave-swap` | single | 4 | predicted FP confirmed, + 1 unpredicted FP |
| `zk-regex-zkapp` | single | 1 | predicted finding, correct |
| `minanft-contract-v2` | single | 8 | predicted findings, correct |
| `o1js-merkle-example` | single | 2 | 2 unpredicted true positives — label was wrong |
| `minauth-treeroot` | single | 0 | correct silence |

Counts are 0.20.0 (`results-0.20.0.json`). `results-0.19.1.json` records the
pre-fix state, where eight of these were zero because nothing was analyzed.

`lumina-pool`'s one real finding is `O1JS_LOGIC_OUTSIDE_PROOF` at `Pool.ts:194`
and `:208`: `setDelegator` and `setProtocol` put their "already defined" guard
inside `Provable.asProver(…)`, which runs outside the circuit and adds no
constraint. A live AMM, invisible for as long as the gate was.

No rate is quoted. Sixteen cases split across two designs share no denominator,
and half of them measured nothing.

Every finding is classified in `triage-0.19.1.json`.

## Two false-positive classes, each now seen in two independent codebases

**Derived-expression state binding.** A value bound to state through a derived
expression — `params.hash()`, `NFTparams.unpack(state)`, `rootBefore` computed
from a witness — is not seen as bound. Four instances across the two corpora:
three `claimTokens` methods in v1's tokenizk-finance, and `buy` here. The
`O1JS_STALE_MERKLE_ROOT` findings on `tradecoin-pair` and `pinsave-swap` are
twelve more, at HIGH.

**Constraint lives in a private helper.** Eighteen findings, four independently
written codebases, and — after 0.20.0 — three different kinds of constraint:

- *signature gating* — `tradecoin-pair`'s `initContract` calls
  `this.checkAdminSignature()`, `pinsave-swap`'s `setFee` calls
  `this.verifyAdminSignature()`; `_method_is_signature_gated` reads the
  `@method` body only;
- *merkle-root binding* — both of the above bind the root inside a helper,
  through a derived local (12 findings, both predicted in advance);
- *proof verification* — silvana's `collection.ts` calls `proof.verify(vk)`
  inside `_update`, which `update()` and `updateWithOracle()` both delegate to.

`helper_binds` has propagated *state* binding through `this.<helper>(…)` chains
since 0.19.0. It propagates none of these three. This is the largest single
source of noise in the corpus and the strongest candidate for the next change —
which is exactly why it is not being made in the release that measured it.

**Authorization gate asserted on the caller, not on the value.** Six findings,
three codebases: silvana's `setName`/`setBaseURL`/`setAdmin`/`transferOwnership`,
MinaFoundation's `setAdmin`, and o1-labs-XT's. Each asserts
`adminContract.canChangeX(value).assertTrue(…)` and then writes `value`. The
assertion gates *who may call*; an admin choosing the next admin is the intent.

`docs/suppression-inversion.md` argues that well-factored code is where this
analyzer false-positives. These two codebases were chosen before that claim was
tested against them, and they confirm it.

## Limitations

Read these before quoting anything above.

- **Sixteen cases, and eight of them measured nothing.** No rate is defensible.
- **The labels are not third-party.** They were written by the same agent that
  wrote several of the rules being evaluated. They were frozen in git before the
  run, which rules out fitting labels to output — but that is weaker than
  independent labelling and should be read that way.
- **One label was wrong, in the tool's favour.** For `o1js-merkle-example` the
  manifest asserts that no rule exists for tautological assertions.
  `O1JS_VACUOUS_ASSERT` exists and fired on exactly the line named. That case
  was also labelled from the `@method` bodies without reading `deploy()`, which
  is where its second finding is. Recorded in `triage-0.19.1.json` rather than
  edited out of the manifest: a label corrected after seeing output is not a
  prediction.
- **The audit findings are the maintainers' own words.** `silvana-lib` publishes
  no audit report; the vulnerability titles come from its commit messages.
- **Two large files were reviewed at method-effect granularity**, not line by
  line: `Lumina Pool.ts` (646 lines) and `TradeCoin PairContract.ts` (548).
- **This corpus is half spent.** The eight cases that were vacuous at 0.19.1
  are the evidence the 0.20.0 gate fix was built on, so they are `development`
  now and are no longer evidence about unseen code. Eight remain held out.
- **`lumina-pool`'s nine `O1JS_WITNESS_NOT_BOUND_TO_STATE` findings are only
  partly reviewed.** Eight sit on pure `@method.returns(UInt64)` calculators and
  are provisionally false positives; tracing the AMM arithmetic against every
  caller was not done. They are recorded as low confidence and should not be
  cited as either a true or a false positive count.
