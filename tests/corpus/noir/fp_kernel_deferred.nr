// @recall-rule NONE
// @recall-expect-absent NOIR_UNCONSTRAINED_WITNESS
fn in_revertible_phase(counter: Field) -> bool {
    // Safety: Kernel will validate that the claim is correct by validating the
    // expected counters.
    let is_revertible = unsafe { is_execution_in_revertible_phase(counter) };
    is_revertible
}
