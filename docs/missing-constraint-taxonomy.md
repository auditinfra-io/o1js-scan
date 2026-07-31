# Missing Constraints as Broken Semantic Edges

*A small taxonomy of application-layer ZK soundness bugs, written from the
perspective of someone who kept seeing the same failure under different SDK
names — and built a scanner to find out how far the pattern went.*

---

ZK security bugs usually get described in framework vocabulary.

In o1js, someone forgot `.assertTrue()` after `.equals()`. In Noir, someone
returned a value from an `unconstrained` function and trusted it. In a recursive
system, someone read `proof.publicOutput` but never verified the proof.

Those descriptions are useful when fixing the line in front of you. They are
less useful for building a mental model, because the dangerous part is not the
API. The dangerous part is that the proof system stopped connecting a value, a
predicate, or a transition to the statement the verifier believes was proved.

The names change. The missing edge does not.

## The semantic edge

```text
  witness / input / prior proof / current state
                 |
                 |  semantic edge
                 v
          constraint or verifier check
                 |
                 v
        statement accepted by verifier
```

A **semantic edge** is the load-bearing connection that turns a program-level
claim into a proof-system fact. It might be an equality constraint, a range
check, a signature verification, a Merkle inclusion proof, a recursive verifier
call, or a state precondition. The implementation differs by framework. The
security role is identical: it prevents the prover from choosing a convenient
world in which the rest of the circuit is true.

Many application-layer ZK bugs reduce to five ways this edge is absent or too
weak:

1. **Unbound witness** — a prover-supplied value is never bound to the fact it
   is supposed to represent.
2. **Non-load-bearing predicate** — a check is computed, but its result is
   never made part of the statement.
3. **Unverified proof edge** — another circuit's statement is treated as true
   without verifying the proof that establishes it.
4. **Unpinned state commitment** — a state value is read, but the transaction
   never requires that the verifier-accepted state still equals what was read.
5. **Missing transition precondition** — a transition is valid only from
   certain prior states, but the circuit never proves it started from one.

This is not an o1js taxonomy or a Noir taxonomy. It is a taxonomy of missing
semantic constraints.

The examples below are real. Where a bug came from live code, it is named and
linked to how it was reported.

---

## 1. Unbound witness

A witness is not suspicious because it is private. Witnesses are the point. The
problem is a witness whose meaning lives only in the programmer's head.

The abstract shape:

```text
let x = witness();
let y = expensive_computation(x);
return y;
```

The computation can be elaborate and still prove the wrong thing. It proves
"there exists an `x` I chose such that `y = f(x)`." It does not prove that `x`
was authorized, came from a committed set, or was the state before the
transaction.

A live instance, from a Mina zkApp:

```ts
const claimedSender: Field = observationProof.publicInput.sender;
claimedSender.assertEquals(
  Poseidon.hash(this.sender.getUnconstrained().toFields())
);
```

This looks like a sender check. It is not one. In o1js,
`this.sender.getUnconstrained()` returns the transaction sender *without proving
it* — the value is not part of the proof. So the assertion compares one
prover-supplied value against another prover-supplied value. Both sides are
free. The constrained form is `getAndRequireSignature()`, which attaches a
signature requirement to the account update.

The edge that should exist — *this address is the one that authorized this
transaction* — is absent, and the code that appears to create it is the code
that doesn't.

## 2. Non-load-bearing predicate

The most common ZK no-op is a check that returns a boolean.

```ts
// make sure this is the right contract by checking if
// the caller is in possession of the correct preimage
commitment.equals(contract_preimage.getCommitment());
```

That comment is the developer's own, from a deployed escrow zkApp. In o1js,
`.equals()` returns a `Bool`. It adds no constraint by itself. Without
`.assertTrue()` — or `.assertEquals()` in the first place — the statement is
inert. Nothing in the circuit prevents a prover from supplying a preimage that
doesn't match the deployed commitment, which means the participant addresses,
amounts, and deadlines the method reasons about are not bound to the contract at
all.

The same line appears five times across five of that contract's six methods.

What makes it a clean finding rather than a guess is the code immediately below
it, which chains `.or(...).or(...).assertTrue()` correctly. The author knew the
idiom. These are oversights, not design decisions — which is exactly why a
reviewer's eye slides over them. The line reads as a check. It has a comment
explaining what it checks. It simply isn't one.

Reported privately to the maintainer; unacknowledged at the time of writing.

## 3. Unverified proof edge

Recursive composition moves a statement across a trust boundary. The verifier
call *is* the boundary.

```ts
@method async verifyRandomNumber(
  observationProof: RandomNumberObservationCircuitProof
) {
  const claimedSender: Field = observationProof.publicInput.sender;
  claimedSender.assertEquals(/* ... */);
  const claimedNetworkState: Field = observationProof.publicInput.networkState;
  this.network.stakingEpochData.ledger.hash.requireEquals(claimedNetworkState);
}
```

There is no `observationProof.verify()` anywhere in that class. In o1js, passing
a `Proof` into a `@method` does not verify it; verification happens only on an
explicit `.verify()` or `.verifyIf(...)`. Without it, the prover supplies the
proof object freely and every field of `publicInput` and `publicOutput` is
unconstrained.

The method constrains the proof's public inputs against the current sender and
network state — and never consumes `publicOutput`, the random value the circuit
exists to produce. So the intended freshness guarantee can be satisfied by
public inputs that merely match the chain, without proving that any PRNG
computation happened.

This one is instructive for a second reason: it was found by a rule that existed
only because of a *false positive*. Suppressing a wrong flag on correct code
required writing down why that code was safe — "the proof is verified" — and the
negation of that condition turned out to be a higher-severity bug that no
detector covered. The [suppression-inversion note](./suppression-inversion.md)
tells that story in full.

Reported privately; unacknowledged at the time of writing.

## 4. Unpinned state commitment

Reading state is not the same as proving what the state was.

```ts
const r = this.root.get();      // no precondition
this.root.set(r.add(1));
```

In o1js, a bare `get()` adds no account precondition. The proof does not bind
`root` to its on-chain value, so a prover can substitute any value and produce a
valid proof of an update computed from it. `getAndRequireEquals()` — or an
explicit `requireEquals(...)` — adds the precondition that makes the read
load-bearing.

The generalization: a root, block value, or accumulator that a circuit consumes
must be tied to the commitment the verifier already accepted. Otherwise the
circuit proves a correct transition out of an imaginary starting point.

Unlike categories 1–3, I have no confirmed field instance of this one to point
at. The shape is canonical and the rule for it is straightforward; it simply
hasn't turned up a true positive in the code I've scanned. That's worth stating
rather than implying otherwise.

## 5. Missing transition precondition

Some transitions are legal only from particular prior states.

```ts
automaton_state.equals(Field(state_deposited));
```

From the same escrow contract as category 2, in the `success` and `failure`
methods. It is the state-machine guard — and it is inert for the same reason:
the comparison result is discarded. Nothing constrains which state those methods
may be invoked from.

Note that this line can be read two ways: as a discarded boolean (category 2) or
as an absent transition guard (category 5). Both readings are correct. That
overlap is a feature of the taxonomy, not a defect in it — more on this below.

---

## Same categories, different surfaces

The right question is never "which API was forgotten?" It is "which fact failed
to enter the constraint system?"

| Concept | Category | o1js | Noir | Halo2 / Plonk-style | Recursive / Solidity verifier |
|---|---|---|---|---|---|
| Boolean not asserted | 2 | `.equals()` result never `.assertTrue()`'d | `bool` from a `check_*` helper never passed to `assert` | Comparison flag computed but not constrained to gate rows | Verifier result or decoded flag not required before accepting state |
| Proof not verified | 3 | `publicOutput` consumed with no `.verify()` | Recursive proof trusted as data, verifier predicate unconstrained | Proof-carrying value exposed without the verifier gadget | Verifier call result trusted without requiring success |
| Hint trusted as fact | 1 | `@method` arg or unconstrained account read used as authenticated state | `unconstrained` fn or oracle result used without relating it to public input | Advice values transformed but not tied to copy constraints or lookups | Public signals treated as verified outputs without binding to the verifier call |
| Field assumed small | 1 | `Field` used as a bounded integer with no `UInt*` or range check | Cast used as range-limited without constraining the original | Field elements read as tags or limbs without range checks | Public inputs decoded as typed values without canonical-encoding checks |
| State read unpinned | 4 | `this.x.get()` with no `requireEquals` | Root or commitment not proved equal to the accepted one | Committed value not tied to the external state root | Prior root accepted without binding it to stored state or parent proof |
| Transition unguarded | 5 | New state written without asserting phase, owner, or nonce | Next state computed without constraining input state tag or nullifier freshness | Transition rows enabled without constraining the state tag | State updated after a valid proof without requiring the expected prior phase |
| Helper name implies enforcement | 2 | `check*` returns `Bool`; caller assumes it asserted | Predicate helper returns `bool`; caller assumes enforcement | Gadget exposes a flag; caller assumes the gadget enforced it | Library returns a success value; wrapper assumes it reverted on failure |
| Domain separation omitted | 1 / 5 | Hash reused across roles with no method or network tag | Commitment checked without the domain fields the protocol assumes | Transcript reused across semantic domains | Proof replayed across contracts, chains, or versions |

## The edges you don't recognize

Locating a missing edge is only half the skill. The other half — the harder half
in practice — is recognizing an edge that *is* present in a form you didn't
expect. Every example below looks like a bug from the previous sections and is
correct code.

**A constraint expressed arithmetically.** From zkEmail's comparison helper:

```rust
let predicate = unsafe { get_lte_predicate_large(x, y) };
let delta = y as Field - x as Field;
let lt_parameter = 2 * (predicate as Field) * delta
                   - predicate as Field - delta + 1;
lt_parameter.assert_max_bit_size::<240>();
```

`predicate` is a hint from an `unconstrained` function — category 1 on its face.
But it is rigorously bound: it is folded into an expression that is only
satisfiable if the hint is correct, and that expression is then range-checked.
There is no `assert(predicate == ...)` anywhere, because that is not how you
constrain a hint in a ZK circuit. The edge is the algebra plus the range check.

**A constraint expressed as an authorization requirement.** From o1-labs' own
token examples:

```ts
const sender = this.sender.getUnconstrained();
const senderUpdate = AccountUpdate.createSigned(sender);
senderUpdate.body.useFullCommitment = Bool(true);
```

This is the same `getUnconstrained()` that was the bug in category 1. Here it is
correct, because `createSigned(sender)` attaches a signature requirement for that
key to the transaction. The unconstrained witness is authenticated by a
requirement built *from* it. The edge exists; it just isn't an assertion.

**A constraint that lives one call away.** From a distributed-key-generation
zkApp: a merkle root is recomputed from a witness and appears unbound — until you
follow `this.verifyFinalizedD(...)` on the line above into an undecorated helper
that does `finalizedDRoot.getAndRequireEquals().assertEquals(witness.calculateRoot(...))`.

That last case generalizes uncomfortably: **the better-factored the codebase, the
more a shallow reviewer or tool will misjudge it.** Good engineers extract
verification into helpers. Any analysis that only reads inside the function body
will systematically flag the most carefully written code.

The review discipline that follows: when you think you've found a missing edge,
your next job is to prove the edge isn't somewhere you didn't look — in the
algebra, in a transaction-level requirement, or one call up.

## Challenging the categories

A taxonomy is only useful if its boundaries survive contact with code, so here
is where these don't.

**The categories are not disjoint.** A stale-state bug can be described as an
unbound witness named `oldRoot`. An ignored predicate can be described as a
missing transition precondition whose guard was computed but never attached —
that is literally the case in category 5 above, which is the same line of code as
category 2. Domain-separation failures look like unbound witnesses because the
value is bound to *something*, just not to the statement the application needs.

The overlap is acceptable if the taxonomy is used as a review instrument rather
than a filing system. The goal is not a perfect label. It is to locate the
missing edge.

**Some ZK bugs are not missing constraints in this sense.** Incorrect algebraic
reductions, unsound custom gates, compiler bugs, bad cryptographic assumptions,
side channels, denial of service, and trusted-setup failures live below or beside
the application statement. This note is about application-layer soundness: cases
where the implementation proves a weaker statement than the protocol description
intends.

The implicit assumption is that the proof system and verifier are sound for the
constraints they actually receive. Under that assumption, a lot of surprising
bugs become unsurprising. The proof system did its job. The wrong statement was
encoded.

## The useful review question

For every security-relevant line:

> **If the prover wanted this fact to be false, where would the circuit stop
> them?**

If the answer is the variable name, the type name, the helper name, the comment,
or the fact that the value came from a proof object — the answer is not a
constraint.

A good review traces the load-bearing edge:

- A witness is bound to a commitment, signature, public input, or prior state.
- A predicate is asserted, or gates a constrained transition.
- A proof is verified before its public values are consumed.
- A state read is pinned to the verifier's accepted current state.
- A transition asserts the old-state condition that makes it legal.
- A domain tag prevents a value proved in one context from being reused in
  another.

Once you can name the missing edge, the framework-specific fix is usually
obvious. Add the assertion. Verify the proof. Pin the state. Prove the range.
Constrain the helper's result. Require the old state. Bind the domain.

## What a tool can and cannot do here

[`o1js-scan`](https://github.com/auditinfra-io/o1js-scan) implements rules for
categories 1 through 4 across o1js and Noir. It is lexical — regex and
brace-matching, not a solver and not a dataflow engine. Both live findings
described above were produced by it.

That shallowness is deliberate and worth explaining, because it bears on where
tooling helps at all. **Proving a circuit is under-constrained requires reasoning
about the constraint system. Noticing that a required call never appears does
not.** The absence of an edge is often a structural fact about the source text,
and structural facts are cheap to check. What is expensive is knowing which edge
was required — and that knowledge is exactly what a taxonomy encodes.

The limits are real and worth stating alongside the claim:

- Aliasing defeats the taint tracking. `const q = qty; send({ amount: q })`
  loses it.
- It is triage, not verification. A clean scan means the obvious edges are
  present, not that the circuit is sound.
- The Noir rules have been calibrated against ten third-party trees and have not
  yet found a true positive in the wild. They are calibrated, not validated —
  a distinction worth preserving rather than papering over.
- Halo2 and Plonky2 are outside what this approach can reach. Their circuits are
  Rust calling a constraint-building API, with no syntactic anchor equivalent to
  `@method` or `unconstrained`, and the relevant property — whether an advice
  cell is tied by a gate or copy constraint — is a fact about the constraint
  system being built, not about the source text. The taxonomy transfers there;
  this technique does not.

## Future work

The natural next step is detector generation from the taxonomy. If a category can
be stated as a missing semantic edge, a tool can often search for the source, the
expected sink, and the absent constraint between them.

Suppression should be inverted. Rather than asking users to silence a false
positive after an API pattern is flagged, a tool should ask them to *name the
constraint that carries the fact*. A valid suppression then becomes lightweight,
machine-checkable documentation of the semantic edge — and, as the RandoMina case
showed, the negation of a suppression condition is frequently a detector nobody
has written.

Better semantic analysis will be needed regardless. The interesting bugs cross
function boundaries, helper abstractions, recursive proof interfaces, and
contract wrappers. Syntax alone will not see enough.

That work is useful precisely because the taxonomy is not tied to o1js or Noir.
It treats framework APIs as surfaces over a smaller question: what fact did the
program need to prove, and where did that fact fail to become a constraint?

---

*Tooling: [`o1js-scan`](https://github.com/auditinfra-io/o1js-scan) — a
dependency-free static soundness linter for o1js/Mina zkApps and Noir circuits.
Apache-2.0. `pip install o1js-scan`. False-positive reports are the most useful
thing anyone can send; real-world code is where the remaining ones are hiding.*
