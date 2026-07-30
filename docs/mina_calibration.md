# Mina / o1js calibration (o1js-scan)

The o1js counterpart to `noir_calibration.md`. Until this pass the o1js side had
**no canary at all**, so the o1js rules could regress silently — which mattered
more than for Noir, because these are the rules that produced the project's only
**confirmed real-world findings**.

Canary: `scripts/mina_canary.sh`.

## Corpus (fourteen repos, pinned)

| Repo | Commit | HIGH budget |
|------|--------|------------:|
| marekyggdrasil/mac | `83cea9cb` | 7 |
| iluxonchik/zkLocus | `600f4068` | 3 |
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
