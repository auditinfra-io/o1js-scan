// The fixed counterpart to noir_unconstrained.nr.
// Run:  o1js-scan examples/noir_constrained.nr   ->  no high/critical findings

unconstrained fn inverse_hint(x: Field) -> Field {
    1 / x
}

fn main(x: Field) -> pub Field {
    // Safety: the returned inverse is re-constrained in-circuit below.
    // FIX: bind the hint with the multiplicative-inverse law `x * inv == 1`.
    // Now the prover cannot return a wrong `inv` — the assert would fail.
    let inv = unsafe { inverse_hint(x) };
    assert(x * inv == 1);
    inv
}
