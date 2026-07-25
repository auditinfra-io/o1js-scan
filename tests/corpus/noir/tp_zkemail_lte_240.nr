// @recall-rule NOIR_UNCONSTRAINED_WITNESS
// @recall-min-severity high
//
// MUTATION of fp_zkemail_lte_240.nr: the ONLY change is deleting the
// `lt_parameter.assert_max_bit_size::<240>();` line. Without it `predicate` is
// a free prover-chosen bool and the circuit proves nothing about x <= y.
pub unconstrained fn get_lte_predicate_large(x: Field, y: Field) -> bool {
    x.lt(y) | (x == y)
}

pub fn lte_field_240_bit(x: Field, y: Field) -> bool {
    // Safety: check the comments below
    let predicate = unsafe { get_lte_predicate_large(x, y) };
    let delta = y as Field - x as Field;
    let lt_parameter = 2 * (predicate as Field) * delta - predicate as Field - delta + 1;

    predicate
}
