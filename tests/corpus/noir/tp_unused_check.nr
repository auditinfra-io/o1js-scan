// @recall-rule NOIR_UNUSED_CHECK_RESULT
// @recall-min-severity high
fn main(w: Field) {
    // Safety: discarded check
    let witness = unsafe { get_w() };
    check_non_membership_with_hasher(w, witness);
}
