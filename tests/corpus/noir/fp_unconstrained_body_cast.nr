// @recall-rule NONE
// @recall-expect-absent NOIR_UNCHECKED_CAST
// @recall-expect-absent NOIR_UNCONSTRAINED_WITNESS
//
// Models noir_json_parser@695b25ad src/getters.nr:271-325, where two narrowing
// casts fired inside `unconstrained fn search_for_key_in_map`. An
// `unconstrained fn` body is Brillig: it runs OUTSIDE the circuit and emits no
// constraints, so a cast there cannot be "missing a range check" — there is no
// circuit to under-constrain. Soundness rests on how the CALLER re-constrains
// the returned value, which NOIR_UNCONSTRAINED_WITNESS checks at the caller's
// `unsafe { ... }` site.
unconstrained fn hint() -> Field { 0 }

unconstrained fn search_for_key_in_map(target: Field) -> u32 {
    let seed = unsafe { hint() };
    let lhs_index = seed + target;
    lhs_index as u32
}
