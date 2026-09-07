# Mina / o1js calibration (o1js-scan)

The o1js counterpart to `noir_calibration.md`. Until this pass the o1js side had
**no canary at all**, so the o1js rules could regress silently — which mattered
more than for Noir, because these are the rules that produced the project's only
**confirmed real-world findings**.

Canary: `scripts/mina_canary.sh`. Benchmark (canary + exact snapshot):
`scripts/mina_benchmark.sh`.

## Reproducible snapshot

The budgets below record *how many* HIGH findings each repo has. That alone
cannot tell one finding from another: a rule could stop firing at `Mac.ts:86`
and start firing somewhere else in the same file, and the count would not move.

[`tests/fixtures/mina_benchmark.json`](../tests/fixtures/mina_benchmark.json)
records every finding — rule, file, line, severity — for all fourteen repos at
the pinned commits below. `scripts/mina_benchmark.sh` runs the budget canary and
then compares the full set, naming each finding that appeared or disappeared.

Three artifacts describe this corpus: the canary's pinned array, the table
below, and the snapshot. `tests/test_scan_snapshots.py` asserts all three agree
on the repo list, the commits and the budgets, offline, so a budget cannot be
raised to silence a finding without the classification this document promises.
Regenerate deliberately, never to make a failure go away:

```bash
python3 scripts/scan_snapshot.py capture tests/fixtures/mina_benchmark.json \
  --kind mina-corpus --target NAME=PATH ...
```

## Corpus (fourteen repos, pinned)

| Repo | Commit | HIGH budget |
|------|--------|------------:|
| marekyggdrasil/mac | `83cea9cb` | 7 |
| iluxonchik/zkLocus | `600f4068` | 4 |
| iluxonchik/randomina | `2d5781a1` | 1 |
| berzanorg/nacho | `db85861e` | 0 |
| berzanorg/xane | `9002bca5` | 2 |
| o1-labs-XT/fungible-token-contract | `a0d42901` | 0 |
| o1-labs-XT/mastermind-zkApp | `bdfc7c91` | 0 |
| Doot-Foundation/contracts | `890c9b0d` | 0 |
| id-Mask/smart-contracts | `9b1e6112` | 0 |
| auxo-zk/Distributed-key-generation | `4d191d78` | 0 |
| izzetemredemir/mina-token-manager | `ec91c922` | 0 |
| 45930/Voting-Playground-o1js | `391ef4b8` | 0 |
| suenchunhui/mina-privacy-coin | `8b30b709` | 0 |
| enderNakamoto/zkMile-contracts | `c15c9c0b` | 0 |

New repos (2026-07-30 Wave 2) were selected from
[MinaFoundation/list-of-projects](https://github.com/MinaFoundation/list-of-projects)
(token / misc categories) for live `o1js` + `SmartContract` sources.

## Wave 3 (0.20.0): the TokenContract gate

Until 0.20.0 the analyzer's contract gate matched `extends SmartContract` and
nothing else, so every `extends TokenContract` zkApp was skipped in silence.
Widening it added **seven findings across this corpus and removed none**. Every
one is classified below, and the zkLocus HIGH budget moves 3 → 4.

Note what this says about the corpus itself: these fourteen repositories were
selected by looking for `extends SmartContract`, the same string the analyzer
keyed on, so the corpus could not have exposed the gap. It took a corpus chosen
by someone else's criterion (`research/heldout-o1js-v2/`, selected by npm
dependency) to find it.

| Location | Rule | Verdict | Reasoning |
|---|---|---|---|
| `zkLocus` `.../bounty/BountyBulletinBoardContract.ts` :229 | `O1JS_APPROVE_WITHOUT_BINDING` | **TP** | `approveUpdate(au: AccountUpdate) { this.approve(au) }` approves a caller-supplied account update with nothing bound. Any caller hands it any update and the token contract approves it. |
| `zkLocus` `.../BountyBulletinBoardContract.ts` :233 | `O1JS_APPROVE_WITHOUT_BINDING` | **TP** | `claimBountyWithApprove(claimAU, bountyId)` approves a caller-supplied update and never reads `bountyId` at all. |
| `zkLocus` `.../BountyBulletinBoardContract.ts` :110, :142 | `O1JS_APPROVE_WITHOUT_BINDING` | **TP** | `sendFromTo(senderAddress, receiverAddress, amount)` runs `this.internal.send({ from: senderAddress, … })` and approves the result, so any caller moves tokens from any address. |
| `zkLocus` `.../tokens/zkl/ZKLContract.ts` :34 | `O1JS_WEAK_PERMISSIONS` (HIGH) | **TP** | `send: Permissions.none()` on the contract's own account in `deploy()` — no proof and no signature is needed to move value out of it. This is the finding that raises the budget to 4. |
| `zkLocus` `.../tokens/zkl/ZKLContract.ts` :34 | `O1JS_WEAK_PERMISSIONS` (MEDIUM) | **FP (by convention)** | `receive: Permissions.none()` is the ordinary setting for an account that is meant to be paid into. The rule counts `receive: none()` among its weak values; on a token contract that is noise. Kept rather than silenced, because narrowing the rule to make this corpus quieter is the move the acceptance criterion exists to prevent. |
| `fungible-token-contract` `src/FungibleTokenContract.ts` :246 | `O1JS_UNCONSTRAINED_WITNESS` | **FP** | `setAdmin(admin)` asserts `canChangeAdmin(admin)` before writing. The gate is on *who* may call, not on the value, and an admin choosing the next admin is the intent. Same class as the "authorization gate in a helper" false positives triaged in `research/heldout-o1js-v2/`; MinaFoundation's own `FungibleToken.ts:138` produces the identical finding. |

The four zkLocus `O1JS_APPROVE_WITHOUT_BINDING` findings are the first real-world
hits for that rule, and they were invisible for as long as the gate was.

## Acceptance criterion

The same one used for Noir: **not "zero HIGH"** — that measures silence, not
discrimination — but that every finding has been read and classified as
TP / FP / UNREVIEWED with reasoning.

The Mina canary adds a second condition the Noir canaries do not have: it fails
when a repo goes **below** its budget as well as above. A confirmed true
positive disappearing is a regression, and without a floor a future suppression
heuristic could delete a disclosed finding and still show a green canary.

## Confirmed true positives — disclosed / pinned

| Location | Rule | Verdict | Reasoning |
|---|---|---|---|
| `mac` `contracts/src/Mac.ts` :86, :182, :306, :326, :346, :366, :386 (7×) | `O1JS_UNASSERTED_BOOL` | **TP** | `commitment.equals(contract_preimage.getCommitment())` returns a `Bool` and adds **no** constraint unless asserted. Seven occurrences of the same shape. |
| `randomina` `src/RandoMinaContract.ts` :69 | `O1JS_UNVERIFIED_PROOF` | **TP** | `observationProof` is a `Proof`-typed `@method` parameter that is never `.verify()`'d. |
| `zkLocus` `.../RandoMinaContract.ts` :69 | `O1JS_UNVERIFIED_PROOF` | **TP** | Same contract, vendored. |
| `zkLocus` `.../RandoMinaContract.ts` :71 | `O1JS_UNCONSTRAINED_SENDER` | **TP (same root cause)** | `this.sender` read without `getAndRequireSignature()`, compared against an unverified proof's public input. |
| `zkLocus` `.../experiments/DeployerVerificationSC.ts` :26 | `O1JS_VACUOUS_ASSERT` | **TP** | `senderDigest.assertEquals(senderDigest)` — self-comparison typo; the surrounding comment says the sender should match the claimed deployee digest. Pinned by `tests/corpus/o1js/tp_regression_zklocus_vacuous_assert.ts`. |
| `xane` `contracts/src/Exchange.ts` :130 (2×) | `O1JS_WEAK_PERMISSIONS` | **TP** | `setVerificationKey: Permissions.none()` and `setPermissions: Permissions.proofOrSignature()` alongside `editState: proofOrSignature` — Mina's documented upgrade training wheels, compound HIGH. |

All confirmed TPs are pinned as regression fixtures under `tests/corpus/o1js/`
(`tp_regression_mac_unasserted_bool.ts`,
`tp_regression_randomina_unverified_proof.ts`,
`tp_regression_zklocus_vacuous_assert.ts`) and the canary enforces HIGH floors.

## Medium / LOW — classified

| Location | Rule | Verdict | Reasoning |
|---|---|---|---|
| `mac` `Mac.ts` :74 | `O1JS_UNCONSTRAINED_WITNESS` | **UNREVIEWED** | `@method` arg reaches a state write; needs off-chain orchestration context. |
| `mac` `Mac.ts` :276 | `O1JS_UNCONSTRAINED_RECIPIENT` | **FP (by design)** | Informational; caller naming their own destination. |
| `zkLocus` 4× `BountyBulletinBoardSC` / `BountySC` / `DeployerSC` / `DeployeeSC` | `O1JS_WEAK_PERMISSIONS` | **TP (low impact)** | Genuinely `proofOrSignature()`/`none()` on `editState`/`send`. MEDIUM. |
| `nacho` `bridge-contract.ts` :42, :63 | `O1JS_WEAK_PERMISSIONS`, `O1JS_UNCONSTRAINED_WITNESS` | **UNREVIEWED** | Bridge operator model; not judged. |
| `xane` `Token.ts` (MEDIUM witnesses) | `O1JS_UNCONSTRAINED_WITNESS` | **UNREVIEWED** | Init / admin-shaped; not judged as HIGH. |
| `mastermind-zkApp` `Mastermind.ts` :48 | `O1JS_WITNESS_NOT_BOUND_TO_STATE` | **UNREVIEWED** | Game contract; impact unclear. |
| `mastermind-zkApp` `Mastermind.ts` :125 | `O1JS_STATE_READ_AFTER_WRITE` | **TP (low impact)** | `setCodeBreakerId()` is called as an argument to `Provable.if`, so the `this.codebreakerId.set(...)` inside it runs on **every** `makeGuess`, not only the first — both branch expressions are ordinary JS arguments, evaluated before `Provable.if` sees them. The paired `getAndRequireEquals()` therefore reads the pre-write on-chain value while the write happens unconditionally. Neutralised in practice by the `computedCodebreakerId.assertEquals(codebreakerId)` that follows, which forces the overwrite to be a no-op, but the code does not do what its `//? If first guess ==> set` comment says. |
| `Distributed-key-generation` `Round2.ts` :622 | `O1JS_UNCONSTRAINED_PROVABLE_WITNESS` | **UNREVIEWED** | DKG protocol; needs cryptographic review. |
| `Distributed-key-generation` `Request.ts` | `O1JS_UNCONSTRAINED_RECIPIENT` | **FP (by design)** | Informational. |
| `Voting-Playground-o1js` 4× | `O1JS_WITNESS_NOT_BOUND_TO_STATE` | **UNREVIEWED** | Named "Playground"; path policy does not downgrade `src/`. |
| `fungible-token-contract` `src/examples/token-manager.eg.ts` | `O1JS_UNCONSTRAINED_SENDER` | **FP (example code)** | Downgraded to LOW by example policy. |
| `mina-privacy-coin` `Sales.ts` | `O1JS_UNCONSTRAINED_WITNESS` | **UNREVIEWED** | Init-state setters; MEDIUM only. Inline `calculateRoot` membership checks correctly suppress `O1JS_STALE_MERKLE_ROOT` after the Wave-2 binding fix. |
| `zkMile-contracts` | (none HIGH) | **clean** | Older `getAndAssertEquals` now recognized as a state-binding form; no HIGH. |

## Wave-2 precision fixes (forced by corpus)

1. **Vacuous assert ignores dotted receivers** —
   `update.body.tokenId.assertEquals(tokenId)` shares a basename but is not a
   self-comparison. Bare `x.assertEquals(x)` still fires.
2. **`getAndAssertEquals` ≡ `getAndRequireEquals`** for state-binding /
   precondition recognition (older o1js API still common in the wild).
3. **Inline Merkle binding** —
   `rootBefore.assertEquals(leafWitness.calculateRoot(...))` counts as a live
   root binding even when the recomputed root is never assigned to a named local.

## Actions / reducers DoS (deferred)

Veridise's reducer-queue brick (unbounded action amounts that permanently stall
`reduce`) remains **out of scope** for the lexical scanner — detecting it
needs protocol-level understanding of which fields are user-supplied vs
canonicalized. Documented here so it is not mistaken for a forgotten backlog
item; do not ship a noisy heuristic without a confirmed wild TP.

## Responsible disclosure

The confirmed true positives were disclosed to their maintainers before being
recorded here (mac / randomina / zkLocus). New findings should follow the same
order — maintainer first, write-up second. The zkLocus vacuous assert and xane
upgrade-permission findings are structural detections on already-public code;
treat them as calibration TPs, not new disclosure packages, unless maintainers
request otherwise.
