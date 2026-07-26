# Mina / o1js calibration (o1js-scan)

The o1js counterpart to `noir_calibration.md`. Until this pass the o1js side had
**no canary at all**, so the o1js rules could regress silently — which mattered
more than for Noir, because these are the rules that produced the project's only
**confirmed real-world findings**.

Canary: `scripts/mina_canary.sh`.

## Corpus (twelve repos, pinned)

| Repo | Commit |
|------|--------|
| marekyggdrasil/mac | `83cea9cb` |
| iluxonchik/zkLocus | `600f4068` |
| iluxonchik/randomina | `2d5781a1` |
| berzanorg/nacho | `db85861e` |
| berzanorg/xane | `9002bca5` |
| o1-labs-XT/fungible-token-contract | `a0d42901` |
| o1-labs-XT/mastermind-zkApp | `bdfc7c91` |
| Doot-Foundation/contracts | `890c9b0d` |
| id-Mask/smart-contracts | `9b1e6112` |
| auxo-zk/Distributed-key-generation | `4d191d78` |
| izzetemredemir/mina-token-manager | `ec91c922` |
| 45930/Voting-Playground-o1js | `391ef4b8` |

## Acceptance criterion

The same one used for Noir: **not "zero HIGH"** — that measures silence, not
discrimination — but that every finding has been read and classified as
TP / FP / UNREVIEWED with reasoning.

The Mina canary adds a second condition the Noir canaries do not have: it fails
when a repo goes **below** its budget as well as above. A confirmed true
positive disappearing is a regression, and without a floor a future suppression
heuristic could delete a disclosed finding and still show a green canary.

## Before / after this pass

Path policy (test suppression, example downgrade) was added in this pass. Its
effect on the corpus is **one finding**, exactly as intended:

| Repo | HIGH before | HIGH after | MED before | MED after | LOW after |
|------|------------:|-----------:|-----------:|----------:|----------:|
| mac | 7 | **7** | 1 | 1 | 1 |
| zkLocus | 2 | **2** | 4 | 4 | 0 |
| randomina | 1 | **1** | 0 | 0 | 0 |
| nacho | 0 | 0 | 2 | 2 | 0 |
| xane | 0 | 0 | 4 | 4 | 0 |
| fungible-token-contract | 0 | 0 | **1** | **0** | **1** |
| mastermind-zkApp | 0 | 0 | 1 | 1 | 0 |
| Distributed-key-generation | 0 | 0 | 1 | 1 | 2 |
| Voting-Playground-o1js | 0 | 0 | 4 | 4 | 0 |
| contracts, smart-contracts, mina-token-manager | 0 | 0 | 0 | 0 | 0 |

**All three confirmed true positives survived** (mac 7 HIGH, zkLocus 2 HIGH,
randomina 1 HIGH). They are all in production `src/` paths, so neither test
suppression nor example downgrading touches them — verified, not assumed, and
now pinned by regression fixtures (below).

The single change is `fungible-token-contract` MEDIUM → LOW: the finding is in
`src/examples/token-manager.eg.ts`, which matches both the `examples/` directory
and the `.eg.` filename rule. It is still reported; it no longer fails a build.

### Note on the 0.5.3 baseline in the task brief

The brief quotes a 0.5.3 baseline of "all others 0". Measured at 0.9.0 the
non-TP repos are not all zero: xane 4, Voting-Playground-o1js 4,
Distributed-key-generation 3, mastermind-zkApp 1, nacho 2. These are **not
regressions** — they are findings from rules that did not exist at 0.5.3
(`O1JS_UNVERIFIED_PROOF`, `O1JS_UNASSERTED_BOOL`, `O1JS_UNCONSTRAINED_SENDER`
all landed in 0.6.0). Reported rather than reconciled.

## Classification of every finding (32 total)

### Confirmed true positives — disclosed

| Location | Rule | Verdict | Reasoning |
|---|---|---|---|
| `mac` `contracts/src/Mac.ts` :86, :182, :306, :326, :346, :366, :386 (7×) | `O1JS_UNASSERTED_BOOL` | **TP** | `commitment.equals(contract_preimage.getCommitment())` returns a `Bool` and adds **no** constraint unless asserted. The result is discarded, so the caller-preimage check the surrounding comment describes ("make sure this is the right contract") is never enforced. Seven occurrences of the same shape. |
| `randomina` `src/RandoMinaContract.ts` :69 | `O1JS_UNVERIFIED_PROOF` | **TP** | `observationProof` is a `Proof`-typed `@method` parameter that is never `.verify()`'d. Passing a proof does not verify it, so `publicInput.sender` and `publicInput.networkState` are prover-controlled and the assertions against them are vacuous. |
| `zkLocus` `contracts/src/blockchain/contracts/RandoMinaContract.ts` :69 | `O1JS_UNVERIFIED_PROOF` | **TP** | The same contract, vendored. Second copy of the finding above. |

All three are **pinned as regression fixtures** in `tests/corpus/o1js/`
(`tp_regression_mac_unasserted_bool.ts`,
`tp_regression_randomina_unverified_proof.ts`) so no future suppression
heuristic can silently delete them, and the canary enforces a HIGH floor.

### Remaining HIGH

| Location | Rule | Verdict | Reasoning |
|---|---|---|---|
| `zkLocus` `.../RandoMinaContract.ts` :71 | `O1JS_UNCONSTRAINED_SENDER` | **TP (same root cause)** | `this.sender` is read without `getAndRequireSignature()`, one line below the unverified proof. The claimed sender is compared against an unverified proof's public input, so neither side is bound. Same defect, same fix. |

### MEDIUM / LOW — classified

| Location | Rule | Verdict | Reasoning |
|---|---|---|---|
| `mac` `Mac.ts` :74 | `O1JS_UNCONSTRAINED_WITNESS` | **UNREVIEWED** | A `@method` argument reaches a state write. Not traced to an exploit; needs the protocol's off-chain orchestration to judge. Flagged honestly rather than assumed benign. |
| `mac` `Mac.ts` :276 | `O1JS_UNCONSTRAINED_RECIPIENT` | **FP (by design)** | Informational rule: a caller naming their own destination. Does not gate CI. |
| `zkLocus` 4× `BountyBulletinBoardSC.ts` :48, `BountySC.ts` :10, `DeployerSC.ts` :23, `DeployeeSC.ts` :19 | `O1JS_WEAK_PERMISSIONS` | **TP (low impact)** | Genuinely `proofOrSignature()`/`none()` on `editState`/`send` — the key holder can bypass the circuit. Correct detection; whether it matters is a deployment-policy question, which is why it is MEDIUM. |
| `nacho` `bridge-contract.ts` :42, :63 | `O1JS_WEAK_PERMISSIONS`, `O1JS_UNCONSTRAINED_WITNESS` | **UNREVIEWED** | Bridge contract; correctness depends on the bridge operator model. Not judged. |
| `xane` `Token.ts` :33–35 (3×), `Exchange.ts` :130 | `O1JS_UNCONSTRAINED_WITNESS`, `O1JS_WEAK_PERMISSIONS` | **UNREVIEWED** | Same shape as above. |
| `mastermind-zkApp` `Mastermind.ts` :48 | `O1JS_WITNESS_NOT_BOUND_TO_STATE` | **UNREVIEWED** | Witness only trivially constrained. Game contract; impact unclear. |
| `Distributed-key-generation` `Round2.ts` :622 | `O1JS_UNCONSTRAINED_PROVABLE_WITNESS` | **UNREVIEWED** | `Provable.witness` result reaching an effect. DKG protocol; needs cryptographic review to judge. |
| `Distributed-key-generation` `Request.ts` :976, :982 | `O1JS_UNCONSTRAINED_RECIPIENT` | **FP (by design)** | Informational. |
| `Voting-Playground-o1js` 4× | `O1JS_WITNESS_NOT_BOUND_TO_STATE` | **UNREVIEWED** | Named "Playground"; likely illustrative, but the path policy does not match it (`src/`, not `examples/`), so it is not downgraded. |
| `fungible-token-contract` `src/examples/token-manager.eg.ts` :130 | `O1JS_UNCONSTRAINED_SENDER` | **FP (example code)** | o1-labs' own deliberately-simplified illustrative code. Downgraded to LOW by the example policy added in this pass — reported, not build-failing. |

**Honest summary: 4 confirmed TPs (3 distinct defects across 2 codebases),
several correct-but-low-impact detections, and 9 UNREVIEWED.** The UNREVIEWED
ones are labelled as such deliberately: judging them needs protocol context this
pass did not have, and marking them FP without that work would be exactly the
"measuring silence" failure this criterion exists to prevent.

## Responsible disclosure

The confirmed true positives were disclosed to their maintainers before being
recorded here. This document names them because they are already disclosed; new
findings should follow the same order — maintainer first, write-up second.
