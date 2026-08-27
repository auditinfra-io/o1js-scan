# Five defects in o1js `DynamicArray`

*Findings from running `o1js-scan` against `o1-labs/o1js`, and the manual audit
that followed. Reported against commit `cc18a91` / npm `o1js@3.0.0`.*

---

## Summary

One of the five is a soundness break: `DynamicArray.get()` and `.set()` document
that they prove the index is inside the array, and under a specific and
*documented* usage pattern they compile to no such proof. The other four are
correctness defects in the same class — a memoised mask read after it went
stale, an off-by-one in `pop(n)`, a membership test that searches the padding,
and a provable type with no canonical form.

All five share one root cause: `DynamicArray` caches values derived from
`length`, and every method that mutates `length` forgets to drop those caches.

| # | Defect | Class | Site |
|---|--------|-------|------|
| 1 | `assertIndexInRange` memoises a bounds proof and never invalidates it, so `get`/`set` silently stop constraining the index once `length` shrinks | **soundness** | `dynamic-array.ts:170-179` |
| 2 | `forEach`/`forEachReverse` use a dummy mask cached against a stale `length` | correctness | `dynamic-array.ts:642-653` |
| 3 | `pop(n)` keeps `i <= length` instead of `i < length`, leaving one popped element behind; `slice()` inherits it | correctness | `dynamic-array.ts:430` |
| 4 | `includes()` scans the whole padded array, ignoring `length` | correctness | `dynamic-array.ts:607-612` |
| 5 | `toCanonical()` is the identity, so logically equal arrays have unequal fields and unequal Poseidon commitments | correctness | `dynamic-array.ts:702-704` |

A patch fixing all five is in
[`research/o1js-dynamic-array/fix.patch`](../research/o1js-dynamic-array/fix.patch);
it applies cleanly to `cc18a91`, and o1js's own `dynamic-array.unit-test.ts`
passes against it with its test body unmodified.

## Reproducing

```bash
cd research/o1js-dynamic-array
npm install                                   # pins o1js@3.0.0
node reproduce.mjs                            # all five, ~10s, no proving
node --stack-size=65500 proof-of-concept.mjs  # finding 1 end-to-end, ~1min
```

`reproduce.mjs` prints each check as `observed` next to `expected`, where
`expected` is what the method's own doc comment promises. On stock `o1js@3.0.0`
eight checks disagree; against the patch, zero do. Nothing in either script
reaches into private state — it is all public API.

---

## Part 1 — what the scanner found, honestly

`scripts/o1js_upstream_canary.sh` against `cc18a91`:

```
all-source: total=39 HIGH=8 MEDIUM=29 LOW=2 files=19
production: total=1  HIGH=0 MEDIUM=1  LOW=0  files=1
```

The "production" pass (tests and examples excluded) reports exactly one finding,
in `benchmark/benchmarks/transaction.ts` — a benchmark fixture. **The scanner
found no exploitable defect in shipped o1js library code.** That is the right
outcome to state plainly: o1js's own `src/lib` is not written in the zkApp
idiom the rules match.

All eight HIGH findings are in `src/examples/`, and on triage all eight are
teaching code doing what it means to do:

* `simple-zkapp-payment.ts` — an unconstrained `amount` reaching `send`, plus a
  prover-chosen sender. This is the minimal payment demo; the whole point is
  that it is minimal.
* `voting/*.ts`, `dummy-contract.ts` — `Permissions.none()` and
  `proofOrSignature()` on `editState` / `setVerificationKey` / `setPermissions`.
  Deliberate: the voting example redeploys contracts across its own test runs.
* The DEX example's `getUnconstrained()` senders are individually annotated
  *"unconstrained because transfer() requires the signature anyway"* — a correct
  argument, and the reason those are MEDIUM rather than HIGH.

One example is worth a second look, though it is not a vulnerability in o1js
itself: `src/examples/zkapps/escrow/escrow.ts:12-17` exposes
`withdraw(user: PublicKey)` which sends 1 MINA to any caller-supplied address
with no authorization at all. The body is a stub — `// add your withdrawal logic
circuit here` — but it is a complete, deployable, drainable contract as written,
under a directory name (`escrow`) that invites copying. A one-line
`this.sender.getAndRequireSignature().assertEquals(user)`, or a comment saying
the method is intentionally incomplete, would cost nothing.

So: the scan is clean, and a clean scan is a real result. It is also where the
automated pass stops, because `o1js-scan`'s rules model *zkApp method bodies* —
witnesses flowing to `send`/state without binding constraints. Nothing in its
rule set models a *library* that memoises constraint emission. Finding 1 below
is invisible to it, and to every other tool of its shape, and that gap is worth
naming rather than papering over.

## Part 2 — the manual audit

`DynamicArray` was the natural place to look next: it is recent, it is the
o1js type whose entire job is index arithmetic on prover-supplied data, and its
own header comment sets up exactly the invariant that the defects below break —

> The _only_ requirement on these is that the length is less or equal capacity.
> In particular, there are no provable guarantees maintained on the content of
> the static-sized array beyond the actual length. Instead, our methods ensure
> integrity of array operations _within_ the actual length.

Everything the class offers rests on that last sentence.

---

## Finding 1 — a bounds proof outlives the length it was proven against

**`src/lib/provable/dynamic-array.ts:170-179`, soundness.**

```ts
assertIndexInRange(i: Field, message?: string): void {
  if (!this.#indicesInRange.has(i)) {
    ...
    i.assertLessThan(this.length, errorMessage);
    this.#indicesInRange.add(i);        // <- remembered forever
  }
}
```

`#indicesInRange` is a `Set<Field>` keyed by variable identity. Once index `i`
has been proven `< length`, every later `get(i)` / `set(i, …)` skips the
constraint. The memo is not a micro-optimisation the caller has to opt into; it
is advertised behaviour, on `get` itself:

> It uses an internal cache to avoid duplication of constraints when the same
> index is used multiple times.

The memo is only valid while `length` holds. But `increaseLengthBy` (`:348`),
`decreaseLengthBy` (`:366`) and `setLengthTo` (`:385`) all reassign
`this.length` and leave `#indicesInRange` untouched — and `pop`, `shiftLeft`,
`slice` and `insert` all route through them. Growing is harmless, since the
valid range only widens. **Shrinking silently drops the bounds proof.**

The result is not a weaker constraint, it is no constraint. `get` falls through
to `getOrUnconstrained` (`:217-232`), whose own doc comment says that if the
index is not in the array "the return value is completely unconstrained", and
warns *"Only use this if you already know/proved by other means that the index
is within bounds"*. The bounds proof is exactly what went missing.

```ts
let arr = Arr.from([10, 20, 30, 40, 50].map(Field)); // length 5, capacity 8
let i = Provable.witness(Field, () => Field(4));     // prover-chosen
arr.get(i);                                          // proves 4 < 5
arr.decreaseLengthBy(Field(3));                      // length is now 2
let v = arr.get(i);                                  // no constraint emitted
```

`Provable.runAndCheck` accepts this and `v` is `50`. Replacing the second `i`
with a freshly witnessed `Field` of the *same value* is rejected with
`assertIndexInRange(): index must be in range [0, length]`, which isolates the
cache as the cause.

It survives real proving. `proof-of-concept.mjs` compiles a `ZkProgram` whose
method reads, to its author, as *"`arr` has exactly 2 elements, `i` is a valid
index into `arr`, and the public output is `arr[i]`"*:

```ts
async method(arr, i) {
  arr.get(i);                      // bounds-checked: proves i < arr.length
  arr.decreaseLengthBy(Field(3));  // arr.length is now 2
  let v = arr.get(i);              // author expects i < 2 to be enforced here
  arr.length.assertEquals(Field(2));
  return { publicOutput: v };
}
```

```
compiled in 38.2s
proof verifies : true
public output  : 50
```

A verifying Kimchi proof asserts the array has length 2 — so the only valid
indices are `{0, 1}` — and returns the element at index 4.

**Impact.** Any circuit that reads or writes through a `DynamicArray` index
variable both before and after the array shrinks. The concrete shape to worry
about is a queue or worklist: `get(i)` an entry, `pop()` the consumed entries,
`get(i)` again on the same index variable and now read an entry that was
removed. The prover picks `i`. Because the first check forces `i < length ≤
capacity`, the second read still lands inside the backing array, so the reachable
window is `[newLength, capacity)` — the logically-removed and never-initialised
slots, not arbitrary field elements. That bounds the blast radius; it does not
make the read sound, and combined with Finding 3 those slots can still hold real
popped values.

## Finding 2 — `forEach` iterates against a stale dummy mask

**`src/lib/provable/dynamic-array.ts:642-653`, correctness.**

`#dummyMask()` derives "which slots are past the end" from `length` and memoises
it in `#dummies`. The same three length mutators never clear it, so any
`forEach` after a length change iterates the array as it used to be:

```ts
let a = Arr.from([1, 2, 3].map(Field));
sumLive(a);      // 6      -- caches the mask for length 3
a.push(Field(10));
sumLive(a);      // 6      -- expected 16; the pushed element reads as a dummy
```

Calling `forEach` only after the `push` gives `16`, so the result depends on
whether the array was ever iterated before. This one is quiet: no assertion
fires, the circuit is satisfiable, the answer is just wrong. `push` is the bad
direction — after `pop` the mask is stale too, but the popped slot has been
nulled, so the arithmetic often still comes out right and hides the defect.

## Finding 3 — `pop(n)` leaves one popped element behind

**`src/lib/provable/dynamic-array.ts:430`, correctness.**

`pop` documents *"The popped positions are set to NULL values"*. The `n`-element
branch runs after `decreaseLengthBy`, so `this.length` is already the new
length, and keeps every slot with `i <= length`:

```ts
this.array[i] = Provable.if(
  new Field(i).lessThanOrEqual(this.length),   // should be lessThan
  this.innerType, this.array[i], NULL);
```

Slot `newLength` is a popped position and is not cleared:

```
[1,2,3,4,5].pop(2)        -> length=3 array=[1,2,3,4,0,0]   expected [1,2,3,0,0,0]
[1,2,3,4,5].pop().pop()   -> length=3 array=[1,2,3,0,0,0]   (no-arg branch is correct)
[1,2,3,4,5].slice(1,3)    -> length=2 array=[2,3,4,0,0,0]   expected [2,3,0,0,0,0]
```

The two branches of the same method disagree, which is what makes this a bug
rather than a padding convention. It matters beyond tidiness for two reasons:
the leftover value is exactly what Finding 1 makes reachable, and it changes the
field encoding — see Finding 5.

## Finding 4 — `includes()` searches the padding

**`src/lib/provable/dynamic-array.ts:607-612`, correctness.**

```ts
includes(value: ProvableValue): Bool {
  let isIncluded = this.array.map((t) => Provable.equal(type, t, value));
  return isIncluded.reduce((acc, curr) => acc.or(curr), new Bool(false));
}
```

`this.array` is the full `capacity`-length backing store. `length` is never
consulted, so the search covers the padding:

```
Arr.from([1,2,3]).includes(0)      -> true    // 0 is NULL padding
[1,2,3,4,5].pop(2).includes(4)     -> true    // 4 was popped
```

The first case is the sharp one: for any element type whose synthesised NULL is
a plausible value, `includes(NULL)` returns true for *every* array that is not
full. For `Field`, `UInt64` and friends that means `includes(0)` is true
whenever `length < capacity`. A membership check is the kind of primitive that
ends up guarding an allowlist, and this one has a permanent false positive
sitting in it.

The existing unit tests do not catch it because they only query values that are
absent from the padding as well, on an array that happens to be full.

## Finding 5 — the type has no canonical form

**`src/lib/provable/dynamic-array.ts:702-704`, correctness.**

```ts
toCanonical(value) {
  return value;
},
```

`toCanonical` exists precisely to normalise representations that differ as field
elements but are equal as values — its own interface doc says so. `DynamicArray`
is the textbook case, since `toFields` emits all `capacity` slots plus `length`,
and everything past `length` is meaningless. Returning the input unchanged means
two arrays with identical content compare unequal:

```ts
let x = Arr.from([1, 2, 3]);
let y = Arr.from([1, 2, 3, 4, 5]); y.pop(Field(2));

x.toValue()                            // [1,2,3]
y.toValue()                            // [1,2,3]
Provable.equal(Arr.provable, x, y)     // false
Poseidon.hash(toFields(x)) === ...(y)  // false
```

`Provable.equal` canonicalises both sides first (`provable.ts:340-341`) and gets
nowhere. So `Poseidon.hash(Arr.provable.toFields(arr))` is not a commitment to
the array — it is a commitment to the array *and its padding*, and which padding
you get depends on how the value was built. `Provable.toCanonical` is also what
`Reducer.dispatch` (`reducer.ts:147`) and `BatchReducer` (`batch-reducer.ts:204`)
apply to actions before hashing, so a `DynamicArray` action type inherits the
same non-determinism at the action-hash level.

Two related notes, analysis only, not demonstrated with an adversarial prover:

* `concat` (`:558-572`) reads `other.getOrUnconstrained(offset)` at offsets past
  `other.capacity` for the tail slots. Those reads are unconstrained by
  `arrayGet`'s own stated assumption, so the padding of a concatenated array is
  prover-influenced rather than merely arbitrary. All such slots sit beyond
  `res.length`, so with a canonical form in place it stops mattering.
* `provable.check` (`:707-710`) validates `length <= capacity` and nothing about
  the padding, which is correct and should stay that way — canonicalisation, not
  extra constraints, is the right place to fix this.

---

## Root cause

`DynamicArray` credits its design to zksecurity's `mina-attestations` and
gretke's `zkApp-data-types`. The reference implementation carries the same three
caches — `_indexMasks`, `_indicesInRange`, `__dummyMask` — with the same absent
invalidation, and it is sound there, because **it has no shrinking operations**.
Its only length mutation is `push`. Growing an array can never invalidate a
proof that `i < length`, and a stale dummy mask under `push` was the one bug
that came along for the ride.

o1js added `pop`, `decreaseLengthBy`, `setLengthTo`, `shiftLeft`, `slice` and
`insert` on top of a caching scheme whose safety argument was "length only ever
grows". The argument was never written down, so it was never rechecked.

The three caches have genuinely different lifetimes, which is the distinction
the code is missing:

| cache | depends on | valid until |
|-------|-----------|-------------|
| `#indexMasks` | the index variable alone | forever |
| `#indicesInRange` | index **and** `length` | `length` changes |
| `#dummies` | `length` | `length` changes |

## The fix

[`research/o1js-dynamic-array/fix.patch`](../research/o1js-dynamic-array/fix.patch)
— 31 insertions, 3 deletions, one file:

1. A `#invalidateLengthCaches()` helper called from all three length mutators.
   It *replaces* the `Set` rather than clearing it in place, so a sibling array
   produced by `map()` (which shares the cache objects, `:267-269`) keeps a memo
   that is still valid for its own unchanged length.
2. `pop(n)`: `lessThanOrEqual` → `lessThan`.
3. `includes()`: mask off the dummies.
4. `toCanonical()`: return a copy with the padding reset to `NULL`.

Validation:

* the patch applies cleanly to `cc18a91` and the file typechecks with no new
  errors;
* `reproduce.mjs` goes from 8 disagreements to 0, and `proof-of-concept.mjs` no
  longer produces a proof — `assertIndexInRange` fires as it should;
* o1js's own `src/lib/provable/test/dynamic-array.unit-test.ts`, including its
  `ZkProgram` compile/prove/verify pass, succeeds unchanged against the patched
  build.

The behavioural validation was done by applying the identical transformation to
the compiled `o1js@3.0.0` bundle, since building o1js from source needs the
OCaml bindings toolchain. The `.ts` patch and the validated `.js` change are the
same edit.

Fixes 1 and 2 are the ones to take first and are behaviour-preserving for any
correct caller. Fixes 3, 4 and 5 change observable results for callers who
depend on today's behaviour — unlikely, given that today's behaviour contradicts
the doc comments in each case, but they are the ones worth a maintainer's
judgement rather than a rubber stamp.

## Suggested regression tests

The existing suite is thorough about values *within* `length` and has no case
that (a) calls `get`/`set`/`forEach` across a length change, (b) inspects the
padding after `pop(n)`, or (c) queries `includes` for a value that is only in
the padding. Those three shapes are what let all five defects through. The
checks in `reproduce.mjs` map one-to-one onto tests in the house style of
`dynamic-array.unit-test.ts`, and are offered for upstream use under this
repository's Apache-2.0 licence.

## Disclosure

As of 2026-08-27 `o1-labs/o1js` ships no `SECURITY.md`, and its GitHub security
page reports no policy configured, so there is no documented private channel to
use. Mina Foundation runs a bug bounty through HackenProof; whether the o1js SDK
falls inside its scope needs confirming rather than assuming.

Finding 1 is a soundness break in a public API, so the intended sequence is:
report it privately first — GitHub private vulnerability reporting on the repo
if maintainers have it enabled, otherwise direct contact with the o1js team —
and hold this document unpublished until they have had a chance to respond.
Findings 2-5 are correctness bugs with no soundness consequence on their own and
can be filed as ordinary public issues at any time.

Nothing here has been sent to o1-labs yet.
