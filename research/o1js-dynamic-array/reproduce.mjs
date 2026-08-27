/**
 * Reproductions for five defects in o1js `DynamicArray`.
 *
 *   npm install o1js@3.0.0
 *   node reproduce.mjs
 *
 * Every check below prints OBSERVED (what stock o1js does) next to EXPECTED
 * (what the method's own documentation promises). Nothing here reaches into
 * private state -- it is all public API.
 */
import { DynamicArray, Field, Poseidon, Provable } from 'o1js';

const Arr = DynamicArray(Field, { capacity: 6 });
const dump = (a) => `length=${a.length} array=[${a.array.map(String)}]`;
const F = (n) => Field(n);

let failures = 0;
function check(label, observed, expected) {
  const ok = observed === expected || observed.startsWith(expected + ' (');
  if (!ok) failures++;
  console.log(
    `  ${ok ? 'ok  ' : 'BUG '} ${label}\n       observed: ${observed}\n       expected: ${expected}`
  );
}
function section(n, title) {
  console.log(`\n=== Finding ${n}: ${title} ===`);
}

async function satisfiable(body) {
  try {
    await Provable.runAndCheck(body);
    return 'constraints satisfied';
  } catch (e) {
    return `constraints rejected (${String(e.message).split('\n')[0]})`;
  }
}

// ---------------------------------------------------------------------------
section(1, 'assertIndexInRange cache outlives the length it was proven against');
// `get()` documents "proves that the index is in the array". The proof is
// memoized per index variable and never invalidated when `length` shrinks, so
// the second `get()` compiles to no bounds constraint at all.

check(
  'reusing the same index variable after a shrink',
  await satisfiable(() => {
    let arr = Arr.from([10, 20, 30, 40, 50].map(F));
    let i = Provable.witness(Field, () => F(4)); // prover-chosen index
    arr.get(i); // legitimate: 4 < 5
    arr.decreaseLengthBy(F(3)); // length is now 2
    let v = arr.get(i); // 4 is not in [0, 2)
    Provable.asProver(() =>
      console.log(`       (this read returned ${v}, the element at index 4)`)
    );
  }),
  'constraints rejected'
);

check(
  'control: fresh index variable, identical value',
  await satisfiable(() => {
    let arr = Arr.from([10, 20, 30, 40, 50].map(F));
    arr.get(Provable.witness(Field, () => F(4)));
    arr.decreaseLengthBy(F(3));
    arr.get(Provable.witness(Field, () => F(4))); // same value, fresh variable
  }),
  'constraints rejected'
);

// ---------------------------------------------------------------------------
section(2, 'forEach uses a dummy mask cached from a stale length');
// `#dummies` is derived from `length` and memoized, but push/pop/shift/setLengthTo
// all reassign `length` without dropping it.
{
  const sumLive = (arr) => {
    let sum = F(0);
    arr.forEach((x, isDummy) => {
      sum = sum.add(Provable.if(isDummy, F(0), x));
    });
    return sum.toString();
  };
  let a = Arr.from([1, 2, 3].map(F));
  check('sum of [1,2,3] before any mutation', sumLive(a), '6');
  a.push(F(10));
  check('sum after push(10), length=' + a.length, sumLive(a), '16');

  let fresh = Arr.from([1, 2, 3].map(F));
  fresh.push(F(10));
  check('same array, forEach called only after the push', sumLive(fresh), '16');
}

// ---------------------------------------------------------------------------
section(3, 'pop(n) leaves the element at the new length in place');
// The loop keeps `i <= length` instead of `i < length`, so one popped slot
// survives. pop() (no argument) does not have the off-by-one.
{
  let a = Arr.from([1, 2, 3, 4, 5].map(F));
  a.pop(F(2));
  check('[1,2,3,4,5].pop(2)', dump(a), 'length=3 array=[1,2,3,0,0,0]');

  let b = Arr.from([1, 2, 3, 4, 5].map(F));
  b.pop();
  b.pop();
  check('[1,2,3,4,5].pop().pop()  (reference behaviour)', dump(b), 'length=3 array=[1,2,3,0,0,0]');

  let c = Arr.from([1, 2, 3, 4, 5].map(F));
  check(
    '[1,2,3,4,5].slice(1,3)  (built on pop)',
    dump(c.slice(F(1), F(3))),
    'length=2 array=[2,3,0,0,0,0]'
  );
}

// ---------------------------------------------------------------------------
section(4, 'includes() scans the padding and ignores length');
{
  let a = Arr.from([1, 2, 3].map(F));
  check(
    '[1,2,3].includes(0)   -- 0 is NULL padding',
    String(a.includes(F(0)).toBoolean()),
    'false'
  );
  check('[1,2,3].includes(2)', String(a.includes(F(2)).toBoolean()), 'true');

  let b = Arr.from([1, 2, 3, 4, 5].map(F));
  b.pop(F(2)); // logical content is [1,2,3]
  check('after pop(2), includes(4) -- 4 was popped', String(b.includes(F(4)).toBoolean()), 'false');
}

// ---------------------------------------------------------------------------
section(5, 'toCanonical() is the identity, so the type has no canonical form');
// Padding is part of toFields(), and toCanonical -- the hook that exists to
// normalise exactly this -- returns its input unchanged. Provable.equal and any
// Poseidon commitment therefore depend on how the array was built.
{
  const hash = (x) => Poseidon.hash(Arr.provable.toFields(x)).toString();
  let x = Arr.from([1, 2, 3].map(F));
  let y = Arr.from([1, 2, 3, 4, 5].map(F));
  y.pop(F(2));

  check(
    'toValue() agrees',
    JSON.stringify(x.toValue().map(String)) + ' vs ' + JSON.stringify(y.toValue().map(String)),
    '["1","2","3"] vs ["1","2","3"]'
  );
  check(
    'Provable.equal on two logically equal arrays',
    String(Provable.equal(Arr.provable, x, y).toBoolean()),
    'true'
  );
  check('Poseidon commitments match', String(hash(x) === hash(y)), 'true');
}

console.log(`\n${failures} of the checks above disagree with the documented behaviour.`);
