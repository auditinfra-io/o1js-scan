# The Five Ways ZK Circuits Accidentally Stop Proving What You Think

*Notes toward a small taxonomy of constraint-system bugs, written from the
perspective of someone who keeps seeing the same failure under different SDK
names.*

---

ZK security bugs often get described in framework vocabulary.

In o1js, someone forgot `.assertTrue()` after `.equals()`.

In Noir, someone returned a value from an `unconstrained` function and trusted
it.

In a recursive system, someone read `proof.publicOutput` but never verified the
proof.

Those are useful descriptions when you are fixing the line in front of you.
They are less useful when you are trying to build a mental model. The dangerous
part is not usually the API. The dangerous part is that the circuit stopped
making the claim the developer thought it was making.

The names change. The failure modes do not.

Most application-layer ZK bugs I see reduce to five categories:

1. **Unconstrained witness** — a value is supplied by the prover but never bound
   to the fact it is supposed to represent.
2. **Ignored predicate** — a check is computed, but the result is not made
   load-bearing.
3. **Unverified proof** — another circuit's statement is treated as true without
   verifying the proof that establishes it.
4. **Stale state commitment** — a state value is read, but the transaction does
   not require the on-chain state still equals the value read.
5. **Missing state precondition** — a transition is valid only from some prior
   state, but the circuit never proves it is starting from that state.

This is not an o1js taxonomy. It is not a Noir taxonomy. It is a constraint
taxonomy.

## 1. Unconstrained witness

A witness is not suspicious because it is private. Witnesses are the point of
ZK. The problem is a witness whose meaning lives only in the programmer's head.

If the prover can choose `age`, `balance`, `secret`, `path`, or `oldRoot`, the
circuit must prove why that choice is the one the verifier should accept.
Sometimes that means a signature check. Sometimes it means a Merkle path.
Sometimes it means a range proof, a hash preimage, or equality against public
input. Without that binding, the witness is just a free variable.

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
inputs is never asserted.

## 2. Ignored predicate

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

## 3. Unverified proof

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

This can be worse than a normal unconstrained witness because the code visually
communicates rigor. Reviewers see a proof type, public inputs, public outputs,
and circuit composition. But unless verification is actually invoked and its
result is enforced by the host framework, the recursive edge is absent from the
constraint graph.

## 4. Stale state commitment

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
binding between `old` and the chain state at execution time.

This is easy to miss because the arithmetic can be perfect. The circuit really
may prove that `new` follows from `old`. It just does not prove that `old` is the
current state. In account-based systems this often becomes a missing
"require equals current value" precondition. In Merkleized systems it becomes a
root, epoch, or commitment that is not pinned to the verifier's accepted state.

## 5. Missing state precondition

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

## Same categories, different surfaces

The table below is deliberately written in concepts first and framework details
second. The right question is not "which API was forgotten?" It is "which fact
failed to enter the constraint system?"

| Concept | Taxonomy category | o1js surface | Noir surface |
| --- | --- | --- | --- |
| Boolean not asserted | Ignored predicate | `.equals()`, `.lessThan()`, or helper-returned `Bool` is computed without `.assertTrue()`, `.assertFalse()`, `.assertEquals()`, or constrained branching. | A `bool` returned by `check_*`, comparison, membership, or range helper is computed but never passed to `assert`, `constrain`, or a constrained branch. |
| Proof not verified | Unverified proof | A `Proof` argument's `publicInput` or `publicOutput` is consumed without calling `.verify()` or otherwise enforcing verification. | A recursive proof, verification key result, or verifier gadget output is trusted as data without constraining the verifier's success predicate. |
| Hint trusted as fact | Unconstrained witness | A method argument, `Provable.witness`, or unconstrained account read is treated as authenticated state or external data without a binding constraint. | An `unconstrained` function, oracle result, or hint supplies a value that is used without proving its relation to public input, a commitment, or another constrained value. |
| Field assumed to be small | Unconstrained witness | A `Field` is used as if it were a bounded integer or boolean without `UInt*`, `Bool`, range checks, or booleanity constraints. | A field element or integer cast is used as if it were range-limited without constraining the original value's range or the cast's validity. |
| State read without pinning | Stale state commitment | `this.x.get()` is used to compute an update without `this.x.requireEquals(...)` or an equivalent account precondition. | A root, commitment, block value, or public state parameter is used without proving it equals the verifier-accepted current commitment. |
| Transition lacks old-state guard | Missing state precondition | A method writes a new state without asserting the previous state, phase, owner, nonce, or nullifier condition required for that transition. | A circuit computes a valid-looking next state without constraining the input state tag, nullifier freshness, membership status, or authorization precondition. |
| Helper name implies enforcement | Ignored predicate | A helper called `check*` or `validate*` returns `Bool`, but callers assume the name means it asserted internally. | A predicate helper returns `bool`, but callers do not assert the returned value because the function name reads like an enforcing check. |

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

Once you can name the missing edge, the framework-specific fix is usually
obvious. Add the assertion. Verify the proof. Pin the state. Prove the range.
Constrain the helper result. Require the old state.

## Why this taxonomy matters

Framework documentation teaches APIs. Audits find broken statements.

The gap between those two is where many ZK bugs live. A developer can know the
API and still forget that a returned boolean is inert. A reviewer can recognize
`Proof` and still miss that verification never happened. A scanner can flag
`this.x.get()` and still need the deeper explanation: the read is not the bug;
the missing state commitment is.

That is why these categories are useful. They let you translate across stacks.
The o1js bug, the Noir bug, the Solidity verifier bug, and the Rust recursion
bug may all wear different syntax. Underneath, each is one of a small number of
ways a program accidentally stops proving what its author thinks it proves.

---

*[o1js-scan](https://github.com/auditinfra-io/o1js-scan) is a dependency-free
static soundness linter for o1js/Mina zkApps and Noir circuits. Apache-2.0.
`pip install o1js-scan`. Issues and false-positive reports welcome — especially
small examples where the missing constraint is obvious to a human and invisible
in syntax.*
