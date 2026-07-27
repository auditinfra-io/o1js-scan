# Every false positive is a detector you haven't written yet

*Notes from building a soundness linter for o1js and Noir, and finding the same
bug class in four unrelated languages.*

---

## The false positive

`o1js-scan` started as a deliberately shallow tool. It does not touch Kimchi,
constraint generation, or the proving system. It reads TypeScript with regular
expressions, extracts `@method` bodies by brace matching, and pattern-matches
against the application-layer soundness model of o1js: `this.x.get()` adds no
account precondition, `@method` arguments are prover-controlled witnesses,
`Field` is not range-bounded.

The first time I pointed it at real zkApps, it flagged this as HIGH:

```ts
@method async submitProof(proof: ExactGeolocationMetadataCircuitProof) {
  proof.verify();
  this.geoPointWithMetadata.set(proof.publicOutput);
}
```

That is correct code. `proof` is a `@method` argument, so lexically it looks
exactly like an unconstrained witness — but once `.verify()` succeeds, the
proof and its `publicOutput` are constrained by the verified circuit. That is
the entire point of recursive proof composition.

So I needed a suppression: *if the body calls `.verify()` on a proof-typed
argument, don't flag it.*

And writing that line is where the interesting part starts.

## The suppression condition is the safety property

To silence a false positive you have to state, precisely, why the flagged code
is actually safe. In this case: **the proof is safe because `.verify()` is
called on it.**

Which means the negation is a bug:

> A proof-typed `@method` argument on which `.verify()` is **never** called.

In o1js, passing a `Proof` into a `@method` does not verify it. Verification
happens only when you explicitly call `.verify()` or `.verifyIf(...)`. Without
it, the prover supplies the proof object freely, and every field of its
`publicInput` / `publicOutput` is unconstrained.

That is a more severe finding than the false positive I set out to fix. It cost
one line of code to add, because I had already done the hard part — articulating
the safety condition — in order to suppress the FP.

The general principle:

> **Every false-positive suppression is a latent detector for its own negation.**
> If you write "this pattern is safe because *X* is present," then "this pattern
> present, *X* absent" is a finding, and it is usually higher severity than the
> FP that prompted it.

## The inverted rule found a real bug

`O1JS_UNVERIFIED_PROOF` did not exist in the morning. On its first run against
real code it hit this, in a live zkApp:

```ts
@method async verifyRandomNumber(
  observationProof: RandomNumberObservationCircuitProof
) {
  const claimedSender: Field = observationProof.publicInput.sender;
  claimedSender.assertEquals(
    Poseidon.hash(this.sender.getUnconstrained().toFields())
  );
  const claimedNetworkState: Field = observationProof.publicInput.networkState;
  this.network.stakingEpochData.ledger.hash.requireEquals(claimedNetworkState);
}
```

There is no `observationProof.verify()` anywhere in the class. The method
constrains the proof's `publicInput` against the current sender and network
state, and never consumes `publicOutput` — the random value the circuit exists
to produce. The intended freshness guarantee can therefore be satisfied by
public inputs that merely match the chain, without proving that any PRNG
computation occurred.

(There is a second, compounding issue in the same four lines:
`this.sender.getUnconstrained()` returns the sender *without* proving it, so
`claimedSender.assertEquals(...)` compares one prover-supplied value against
another. `getAndRequireSignature()` is the constrained form.)

Reported privately to the maintainer. Unacknowledged at time of writing.

## The same shape, one language over

Running the same inversion pass on the rest of the rule set produced a second
detector: a comparison whose result is computed and then discarded.

```ts
// make sure this is the right contract by checking if
// the caller is in possession of the correct preimage
commitment.equals(contract_preimage.getCommitment());
```

In o1js, `.equals()` returns a `Bool`. It constrains nothing by itself. Without
`.assertTrue()` — or `.assertEquals()` in the first place — the statement is a
no-op in the circuit.

This is from a deployed escrow zkApp. The same line appears five times, plus two
occurrences of a state-machine guard, across five of the contract's six methods:
`deposit`, `withdraw`, `success`, `failure`, `cancel`. The developer's own
comment states the intent. The check does not exist in the circuit.

What makes it a clean finding rather than a guess is the code immediately below
it, which chains `.or(...).or(...).assertTrue()` correctly. The author knew the
idiom. These seven are an oversight, not a design decision.

Reported privately. Unacknowledged at time of writing.

## Four languages, one bug class

Once you have the shape, it stops looking language-specific.

**o1js** — a `Proof` argument with no `.verify()`; a `Bool` from `.equals()`
never asserted.

**Noir** — a hint pulled from an `unsafe` block and never constrained; a
predicate computed and never enforced.

```rust
let x = check_something(a, b);   // returns bool
// ... never asserted
```

**Solidity** — a recovered address or validity flag that never gates anything:

```solidity
address signer = ecrecover(hash, v, r, s);
token.transfer(to, amt);         // signer is never compared to anything
```

The same applies to `SignatureChecker.isValidSignatureNow`, ERC-1271's magic
value, `MerkleProof.verify` — all return a verdict the caller must enforce.

**Rust / ZK verifier programs** — a proof verified, and the result dropped:

```rust
let _ = verify_proof(&proof);
insert_nullifiers(ctx.accounts, &proof.nullifiers)?;
```

The abstract shape is the same in all four:

> **A verdict is computed, and then not made load-bearing.**

The security-relevant work — recovering a signer, verifying a proof, comparing
a commitment — actually happens. It simply doesn't gate anything. Nothing
reverts, nothing constrains, no assertion is added to the circuit. The code
reads, to a human and often to a reviewer, as though the check is present.

## Why a lexical tool can catch this

It's worth being clear about why an unsophisticated tool finds a serious class
of bug: **this is a structural absence, not a semantic property.**

Proving that a circuit is genuinely under-constrained requires reasoning about
the constraint system. That is a much harder tool and a much better one. But
noticing that a returned value is never used, or that a required call never
appears, does not require a solver. It requires knowing which call is required
— which is exactly the knowledge you are forced to write down when you suppress
a false positive.

## The counter-discipline

The technique has an obvious failure mode: it is very easy to "fix" a false
positive by making a rule quieter, and every FP fixed that way is a silent
false negative. Silence looks identical to correctness in a scanner report.

So every suppression in `o1js-scan` ships with a paired fixture:

- `fp_<case>.nr` — the real-world code verbatim, must produce **no** finding
- `tp_<case>.nr` — the same code with **only** the constraining construct
  removed, must produce the finding again

If the `tp_` variant doesn't fire, the suppression is over-broad and the rule
has been gutted rather than calibrated. This matters more than it sounds:
calibration runs against large third-party trees make "zero findings" feel like
success, and zero is also what a broken rule produces.

A related lesson from the same corpus: **the better-factored the codebase, the
more you false-positive.** Good engineers extract verification into helpers, so
a linter that only reads inside the function body will systematically flag the
most carefully written projects. One HIGH in this corpus turned out to be a
merkle-root check that was correct — the binding lived in an undecorated helper
one call away. Following helper calls one level deep removed a whole class of
FPs concentrated, by construction, in the best code.

## What this doesn't prove

- **Not a soundness proof.** `o1js-scan` is lexical triage. It gets you to the
  right lines fast; it does not verify a circuit.
- **Aliasing defeats it.** `const q = qty; this.send({ amount: q })` loses the
  taint. Documented, not fixed.
- **The Noir rules have no confirmed true positive in the wild.** They have been
  calibrated against ten third-party trees — aztec-nr, zkpassport, the official
  `noir-lang` libraries, zkEmail — and every finding on those trees was read and
  classified as a false positive. The rules are calibrated; they are not yet
  validated. That distinction is worth stating rather than presenting the zero
  as a result.
- **Two disclosures, neither confirmed.** Both were reported privately and
  neither has been acknowledged. The findings are argued from source; the
  maintainers have not agreed with them.
- **The Solidity and Rust variants above are gaps, not field findings.** They
  were identified by running the same inversion pass over a private engine's
  suppression logic. No third-party bug is claimed for either.

## The procedure, if you want to run it

1. Inventory every condition in your analyzer that suppresses or downgrades a
   finding — guards, allowlists, early `continue`, severity demotions, and any
   comment of the form "safe because X."
2. For each, write the inverse as a one-line finding title: *dangerous pattern
   present, safety condition absent.*
3. Check whether anything already emits it. Be honest about UNKNOWN.
4. Rank the gaps by whether the inverse is exploitable, not by how easy it is to
   detect.
5. Implement with paired mutation fixtures, or you will ship silence.

The suppressions are already written. They encode security knowledge you have
paid for in debugging time. Most analyzers never read them back.

---

*[o1js-scan](https://github.com/auditinfra-io/o1js-scan) is a dependency-free
static soundness linter for o1js/Mina zkApps and Noir circuits. Apache-2.0.
`pip install o1js-scan`. Issues and false-positive reports welcome — real-world
FPs are the most useful thing anyone can send.*
