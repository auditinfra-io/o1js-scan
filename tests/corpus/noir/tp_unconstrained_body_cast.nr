// @recall-rule NOIR_UNCHECKED_CAST
// @recall-min-severity medium
//
// MUTATION of fp_unconstrained_body_cast.nr: the body is IDENTICAL; the ONLY
// change is dropping the `unconstrained` keyword from the second function, so
// it becomes circuit code. Now the cast really is missing a range check — a
// prover-controlled Field narrowed to u32 truncates — and the unsafe hint
// really is unconstrained, so both rules must fire.
//
// This is what bounds the suppression: it silences Brillig bodies, not circuit
// code. If this fixture ever goes silent, the suppression has become
// over-broad and is hiding real findings.
unconstrained fn hint() -> Field { 0 }

fn search_for_key_in_map(target: Field) -> u32 {
    let seed = unsafe { hint() };
    let lhs_index = seed + target;
    lhs_index as u32
}
