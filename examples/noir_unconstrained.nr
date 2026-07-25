// A DELIBERATELY VULNERABLE Noir circuit for demonstrating o1js-scan's Noir rules.
// Run:  o1js-scan examples/noir_unconstrained.nr

// An unconstrained function is only a prover HINT — it runs outside the circuit,
// so a malicious prover can make it return anything.
unconstrained fn inverse_hint(x: Field) -> Field {
    1 / x
}

fn main(x: Field) -> pub Field {
    // BUG: `inv` is taken from an unconstrained hint and then USED as the
    // circuit's output without ever asserting `x * inv == 1`. The prover can
    // return any `inv`, so the circuit proves nothing about it.
    //   -> NOIR_UNCONSTRAINED_WITNESS (high)
    // This unsafe block also lacks the conventional safety note (flagged low).
    let inv = unsafe { inverse_hint(x) };
    inv
}
