# o1js `DynamicArray` — reproductions

Supporting material for
[`docs/o1js-upstream-findings.md`](../../docs/o1js-upstream-findings.md).

Target: `o1-labs/o1js` commit `cc18a91`, published as `o1js@3.0.0`.

```bash
npm install                                   # pins o1js@3.0.0
node reproduce.mjs                            # all five findings, ~10s
node --stack-size=65500 proof-of-concept.mjs  # finding 1 end-to-end, ~1min
```

## `reproduce.mjs`

Public API only — nothing reaches into private state. Each check prints what
stock o1js does next to what the method's own doc comment promises.

On `o1js@3.0.0`, eight checks disagree:

```
  BUG  reusing the same index variable after a shrink
  BUG  sum after push(10), length=4
  BUG  [1,2,3,4,5].pop(2)
  BUG  [1,2,3,4,5].slice(1,3)  (built on pop)
  BUG  [1,2,3].includes(0)   -- 0 is NULL padding
  BUG  after pop(2), includes(4) -- 4 was popped
  BUG  Provable.equal on two logically equal arrays
  BUG  Poseidon commitments match
8 of the checks above disagree with the documented behaviour.
```

With `fix.patch` applied: `0 of the checks above disagree`.

## `proof-of-concept.mjs`

Compiles and proves a `ZkProgram` whose method asserts the array has length 2
and returns the element at a prover-chosen index 4. On `o1js@3.0.0`:

```
proof verifies : true
public output  : 50
```

On a fixed build it exits cleanly with `assertIndexInRange(): index must be in
range [0, length]`.

## `fix.patch`

Against `src/lib/provable/dynamic-array.ts` at `cc18a91` — 31 insertions, 3
deletions:

```bash
git -C /path/to/o1js apply /path/to/fix.patch
```

Behaviour was validated by applying the identical change to the compiled
`o1js@3.0.0` bundle in `node_modules`, because building o1js from source needs
the OCaml bindings toolchain. Against the patched build, both scripts above
report a clean result and o1js's own `src/lib/provable/test/dynamic-array.unit-test.ts`
passes with its test body unmodified (only its imports were repointed at the
installed package), including its `ZkProgram` compile/prove/verify pass.
