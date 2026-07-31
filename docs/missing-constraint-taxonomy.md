# Missing Constraints as Broken Semantic Edges

_Notes toward a small taxonomy of constraint-system bugs, written from the
perspective of someone who keeps seeing the same failure under different SDK
names._

---

ZK security bugs often get described in framework vocabulary.

In o1js, someone forgot `.assertTrue()` after `.equals()`.

In Noir, someone returned a value from an `unconstrained` function and trusted
it.

In a recursive system, someone read `proof.publicOutput` but never verified the
proof.

Those are useful descriptions when fixing the line in front of you. They are
less useful when building a mental model. The dangerous part is usually not the
API. The dangerous part is that the proof system stopped connecting a value, a
predicate, or a transition to the statement the verifier believes was proved.

The names change. The missing edge does not.

A useful abstraction is the **semantic edge**:

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

A semantic edge is the load-bearing connection that turns a program-level claim
into a proof-system fact. It may be an equality constraint, a range constraint, a
signature verification, a Merkle inclusion proof, a recursive verifier call, or
a state precondition. The implementation differs by framework. The security
role is the same: it prevents the prover from choosing a convenient world in
which the rest of the circuit is true.

Many application-layer ZK bugs reduce to five ways this edge is absent or too
weak:

1. **Unbound witness** — a value is supplied by the prover but never bound to
   the fact it is supposed to represent.
2. **Non-load-bearing predicate** — a check is computed, but the result is not
   made part of the statement.
3. **Unverified proof edge** — another circuit's statement is treated as true
   without verifying the proof that establishes it.
4. **Unpinned state commitment** — a state value is read, but the transaction
   does not require the verifier-accepted state still equals the value read.
5. **Missing transition precondition** — a state transition is valid only from
   some prior state, but the circuit never proves it is starting from that
   state.

This is not an o1js taxonomy. It is not a Noir taxonomy. It is a taxonomy of
missing semantic constraints.

## 1. Unbound witness

A witness is not suspicious because it is private. Witnesses are the point of
ZK. The problem is a witness whose meaning lives only in the programmer's head.

If the prover can choose `age`, `balance`, `secret`, `path`, or `oldRoot`, the
circuit must prove why that choice is the one the verifier should accept.
Sometimes that means a signature check. Sometimes it means a Merkle path.
Sometimes it means a range proof, a hash preimage, or equality against public
input. Without that binding, the witness is just a free variable with a good
name.

The misleading version looks like this:

```text
let x = witness();
let y = expensive_computation(x);
return y;
```

The computation can be elaborate and still prove the wrong thing. It proves
"there exists an `x` I chose such that `y = f(x)`." It does not prove "this `x`
was authorized," "this `x` came from the committed set," or "this `x` was the
state before the transaction."

In o1js, this often appears as a `@method` argument, a `Field` with an assumed
range, or an unconstrained account value. In Noir, it often appears around
`unconstrained` functions, hints, casts, and values whose relationship to public
inputs is never asserted. In Plonk-style and Halo2 circuits, the same error may
appear as advice values that are assigned and then only locally transformed, not
connected to the lookup, equality, range, or public-input relation that gives
them meaning.

## 2. Non-load-bearing predicate

The most common ZK no-op is a check that returns a boolean.

A human reads this:

```text
is_valid_signature(message, signature, public_key);
transfer(asset, recipient);
```

and sees a signature check. A circuit sees a boolean value that was computed and
then discarded.

The distinction matters because constraint systems do not enforce intent. A
comparison can allocate constraints for the comparison itself, but unless the
result is asserted, branched on in a constrained way, or otherwise used to gate a
state change, the predicate is not part of the statement being proven.

The predicate must become load-bearing:

```text
             predicate computed
                    |
        +-----------+-----------+
        |                       |
        v                       v
  asserted true           gates transition
        |                       |
        +-----------+-----------+
                    |
                    v
          accepted statement depends on it
```

This category includes:

- equality checks whose `Bool` result is ignored;
- range checks that return `true` or `false` but are never asserted;
- membership checks whose verdict is dropped;
- helper functions named `check_*` that return a predicate instead of enforcing
  it;
- boolean values that are expected to be boolean but are never constrained to
  `0` or `1`.

The bug is not that no work happened. The bug is that the work did not become a
constraint that the proof must satisfy.

## 3. Unverified proof edge

Recursive proofs create a particularly sharp version of the same problem.

A proof object is not magic. Its public input and public output are just data
unless the surrounding circuit verifies the proof. If a program reads
`proof.publicOutput` before verifying the proof, it is reading a claim, not a
fact.

The intended statement is usually:

> I prove that this other proof was valid, and therefore I may consume its public
> output.

The buggy statement is:

> I accept a value shaped like a proof, and I use the public output field the
> prover supplied.

This can be worse than a normal unbound witness because the code visually
communicates rigor. Reviewers see a proof type, public inputs, public outputs,
and circuit composition. But unless verification is actually invoked and its
success condition is enforced by the host framework, the recursive edge is
absent from the proof graph.

```text
 correct recursion                  broken recursion

 proof A statement                  proof A-shaped data
        |                                  |
        v                                  v
 verify proof A                      read publicOutput
        |                                  |
        v                                  v
 use A.publicOutput                  prove statement B
        |
        v
 prove statement B
```

The same pattern appears outside recursive circuits. A Solidity verifier wrapper
that decodes public signals but fails to require the verifier call to succeed is
also missing the edge from proof verification to accepted application state.
The syntax is different; the trust transition is the same.

## 4. Unpinned state commitment

State reads are another place where code can look right while the circuit proves
too little.

A method may read a balance, root, nonce, epoch, owner, or configuration value
and then compute a correct transition from that value. But if the transaction
does not require that the live state still equals the value read, the proof may
be valid for a stale snapshot.

The shape is:

```text
old = read_state();
new = transition(old, witness);
write_state(new);
```

The missing constraint is not inside `transition`. The missing constraint is the
binding between `old` and the verifier-accepted state at execution time.

```text
       chain / verifier state commitment
                    |
                    |  must equal
                    v
              old state value
                    |
                    v
              transition proof
                    |
                    v
              new commitment
```

This is easy to miss because the arithmetic can be perfect. The circuit really
may prove that `new` follows from `old`. It just does not prove that `old` is the
current state. In account-based systems this often becomes a missing
"require equals current value" precondition. In Merkleized systems it becomes a
root, epoch, or commitment that is not pinned to the verifier's accepted state.
In rollups and recursive accumulators, it may be an accumulator root or previous
proof output that is used without binding it to the parent statement.

## 5. Missing transition precondition

Some bugs are not about a single value being unconstrained. They are about a
transition being allowed from the wrong phase of a state machine.

A withdrawal may be valid only after `Closed`. A cancellation may be valid only
before `Funded`. A nullifier may be valid only if it has not already been used.
An administrator action may be valid only while a key is active.

If the circuit proves the output state but not the required input state, it has
proved an incomplete transition.

The shape is:

```text
// intended: only from PENDING
state = read_state();
perform_finalization();
state = FINALIZED;
```

If `state == PENDING` is not enforced, the finalization logic may be reachable
from every state. This is separate from stale state: even if the state read is
fresh, the program may still fail to prove the specific precondition that makes
the transition legal.

This category overlaps with unpinned state commitments in real programs. The
difference is useful during review. Pinning asks whether the state is the one
the verifier currently accepts. A transition precondition asks whether that
state has the semantic property required for this transition.

## Same categories, different surfaces

The table below is deliberately written in concepts first and framework details
second. The right question is not "which API was forgotten?" It is "which fact
failed to enter the constraint system?"

| Concept                          | Taxonomy category                      | o1js surface                                                                                                                                              | Noir surface                                                                                                                                                                | Halo2 / Plonk-style surface                                                                                                             | Recursive / Solidity verifier surface                                                                                                          |
| -------------------------------- | -------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| Boolean not asserted             | Non-load-bearing predicate             | `.equals()`, `.lessThan()`, or helper-returned `Bool` is computed without `.assertTrue()`, `.assertFalse()`, `.assertEquals()`, or constrained branching. | A `bool` returned by `check_*`, comparison, membership, or range helper is computed but never passed to `assert`, `constrain`, or a constrained branch.                     | A selector, lookup result, comparison flag, or advice-derived predicate is computed but not constrained to gate the relevant rows.      | A verifier result, decoded flag, or application predicate is computed but not required before accepting state.                                 |
| Proof not verified               | Unverified proof edge                  | A `Proof` argument's `publicInput` or `publicOutput` is consumed without calling `.verify()` or otherwise enforcing verification.                         | A recursive proof, verification key result, or verifier gadget output is trusted as data without constraining the verifier's success predicate.                             | A proof-carrying value is exposed to the circuit without adding the verifier gadget or constraining its output.                         | A recursive proof output, aggregator result, or Solidity verifier call is trusted without requiring successful verification.                   |
| Hint trusted as fact             | Unbound witness                        | A method argument, `Provable.witness`, or unconstrained account read is treated as authenticated state or external data without a binding constraint.     | An `unconstrained` function, oracle result, or hint supplies a value that is used without proving its relation to public input, a commitment, or another constrained value. | Advice columns receive values that are transformed but not connected to copy constraints, lookups, commitments, or public inputs.       | Public signals or calldata are treated as if they were outputs of a verified proof, without binding them to the verifier call.                 |
| Field assumed to be small        | Unbound witness                        | A `Field` is used as if it were a bounded integer or boolean without `UInt*`, `Bool`, range checks, or booleanity constraints.                            | A field element or integer cast is used as if it were range-limited without constraining the original value's range or the cast's validity.                                 | Field elements are interpreted as tags, indices, bytes, or limbs without the range checks or lookups that justify that interpretation.  | Public inputs are decoded as typed values without checking canonical encoding, range, or domain separation where the application relies on it. |
| State read without pinning       | Unpinned state commitment              | `this.x.get()` is used to compute an update without `this.x.requireEquals(...)` or an equivalent account precondition.                                    | A root, commitment, block value, or public state parameter is used without proving it equals the verifier-accepted current commitment.                                      | A committed value or instance column is not tied to the external state root or accumulator expected by the verifier.                    | A previous root, rollup state, accumulator, or public signal is accepted without binding it to the contract's stored value or parent proof.    |
| Transition lacks old-state guard | Missing transition precondition        | A method writes a new state without asserting the previous state, phase, owner, nonce, or nullifier condition required for that transition.               | A circuit computes a valid-looking next state without constraining the input state tag, nullifier freshness, membership status, or authorization precondition.              | Transition rows are enabled without constraining the state tag, selector discipline, nullifier set relation, or authorization relation. | A verifier wrapper updates contract state after a valid proof but does not require the expected prior phase, root, sender role, or nonce.      |
| Helper name implies enforcement  | Non-load-bearing predicate             | A helper called `check*` or `validate*` returns `Bool`, but callers assume the name means it asserted internally.                                         | A predicate helper returns `bool`, but callers do not assert the returned value because the function name reads like an enforcing check.                                    | A chip or gadget exposes an output flag but the caller assumes the gadget enforced the policy internally.                               | A library returns a success value or decoded proof data but the wrapper assumes the call reverted on failure.                                  |
| Domain separation omitted        | Unbound witness / missing precondition | A hash, signature, or public input is reused across roles without constraining a method tag, network tag, or account identity.                            | A commitment or signature is checked without constraining the domain fields the protocol assumes.                                                                           | A transcript, lookup table, or commitment is used across semantic domains without the tags needed to prevent reinterpretation.          | A proof or public signal is replayed across contracts, chains, circuits, or versions because the accepted statement omits the intended domain. |

## Challenging the categories

A taxonomy is useful only if its boundaries survive contact with code.

The categories above are not disjoint. A stale state bug can also be described
as an unbound witness named `oldRoot`. An ignored predicate can be seen as a
missing transition precondition whose guard was computed but never attached.
Domain-separation failures often look like unbound witnesses because the value
is bound to _something_, just not to the statement the application needs.

The overlap is acceptable if the taxonomy is used as a review instrument rather
than as a filing system. The goal is not to assign a perfect label. The goal is
to locate the missing semantic edge.

There are also limits. Some ZK bugs are not missing constraints in this sense:
incorrect algebraic reductions, unsound custom gates, compiler bugs, bad
cryptographic assumptions, side channels, denial-of-service, and trusted setup
failures may live below or beside the application statement. This note is about
application-layer soundness bugs where the implementation proves a weaker
statement than the protocol description intends.

The implicit assumption is that the underlying proof system and verifier are
sound for the constraints they actually receive. Under that assumption, many
surprising bugs become less surprising: the proof system did its job. The wrong
statement was encoded.

## The useful review question

For every security-relevant line, ask:

> If the prover wanted this fact to be false, where would the circuit stop them?

If the answer is "the variable name," "the type name," "the helper name," "the
comment," or "the fact that this value came from a proof object," the answer is
not a constraint.

A good review traces the load-bearing edge:

- A witness is bound to a commitment, signature, public input, or prior state.
- A predicate is asserted or used to gate a constrained transition.
- A proof is verified before its public values are consumed.
- A state read is pinned to the verifier's accepted current state.
- A transition asserts the old-state condition that makes it legal.
- A domain tag prevents a value proved in one context from being reused in
  another.

Once you can name the missing edge, the framework-specific fix is usually
obvious. Add the assertion. Verify the proof. Pin the state. Prove the range.
Constrain the helper result. Require the old state. Bind the domain.

## Why this taxonomy matters

Framework documentation teaches APIs. Audits find broken statements.

The gap between those two is where many ZK bugs live. A developer can know the
API and still forget that a returned boolean is inert. A reviewer can recognize
`Proof` and still miss that verification never happened. A scanner can flag
`this.x.get()` and still need the deeper explanation: the read is not the bug;
the missing state commitment is.

That is why this taxonomy is useful beyond naming bugs.

For code review, it gives reviewers a short checklist of semantic edges to
trace. Instead of reading for suspicious syntax, the reviewer asks whether every
security-relevant value reaches the accepted statement through a constraint.

For detector design, it suggests that useful tools should model missing edges,
not merely forbidden calls. A detector for ignored predicates, unpinned state, or
unverified proof outputs is stronger when it reports the absent binding: the
predicate that never became load-bearing, the state read that never became a
precondition, or the proof output that crossed a trust boundary without a
verification edge.

For audit methodology, it separates local API mistakes from protocol statement
mistakes. That distinction helps auditors decide whether a finding is a small
patch, a missing invariant, or evidence that the written specification does not
say what the circuit must prove.

For static analysis, the taxonomy points toward dataflow and control-flow
questions that are portable across languages: which values are witness-derived,
which predicates dominate state updates, which verifier results guard public
signal consumption, and which commitments are tied to external state.

For teaching, it replaces a list of SDK footguns with one durable lesson: a
proof only proves the constraints that connect witnesses, predicates, prior
proofs, and state commitments to the verifier's statement.

The o1js bug, the Noir bug, the Halo2 gadget bug, the recursive SNARK bug, and
the Solidity verifier bug may all wear different syntax. Underneath, each is one
of a small number of ways a program accidentally stops proving what its author
thinks it proves.

## Future work

The next step is detector generation from the taxonomy. If a category can be
stated as a missing semantic edge, a tool can often search for the source, the
expected sink, and the absent constraint between them.

Suppression should also be inverted. Instead of asking users to silence false
positives after an API pattern is flagged, tools should ask them to identify the
constraint that carries the fact. A valid suppression would become lightweight
machine-checkable documentation of the semantic edge.

Better semantic analysis will be needed. The interesting bugs cross function
boundaries, helper abstractions, recursive proof interfaces, contract wrappers,
and language boundaries. Syntax alone will not see enough. Cross-language
security tooling should track claims as they move from circuit code to verifier
code to application state.

That work is useful precisely because the taxonomy is not tied to o1js or Noir.
It treats framework APIs as surfaces over a smaller question: what fact did the
program need to prove, and where did that fact fail to become a constraint?
