// @recall-rule NONE
// @recall-expect-absent NOIR_UNCONSTRAINED_WITNESS
fn confirm_hinted_note(hinted_note: Field, slot: Field) {
    assert(hinted_note != 0);
    assert(slot != 0);
}
fn get_note(slot: Field) -> Field {
    // Safety: The note is constrained below.
    let hinted_note = unsafe { view_note() };
    confirm_hinted_note(hinted_note, slot)
}
