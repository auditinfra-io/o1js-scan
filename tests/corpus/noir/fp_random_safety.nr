// @recall-rule NONE
// @recall-expect-absent NOIR_UNCONSTRAINED_WITNESS
fn create_note(owner: Field) -> Field {
    // Safety: We use the randomness to preserve privacy; the sender already
    // knows the note pre-image and is trusted not to disclose it.
    let randomness = unsafe { random() };
    owner + randomness
}
