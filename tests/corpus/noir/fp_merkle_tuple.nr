// @recall-rule NONE
// @recall-expect-absent NOIR_UNCONSTRAINED_WITNESS
fn assert_nullifier_did_not_exist_by(root: Field, nullifier: Field) {
    // Safety: magical values for the proof below.
    let (low_leaf_preimage, witness) = unsafe { get_low_nullifier_membership_witness(root, nullifier) };
    assert(!low_leaf_preimage.is_empty());
    let (non_inclusion, is_valid_low_leaf, low_leaf_exists) = check_non_membership_with_hasher(
        nullifier,
        low_leaf_preimage,
        witness,
        root,
    );
    assert(low_leaf_exists);
    assert(is_valid_low_leaf);
    assert(non_inclusion);
}
