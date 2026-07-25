// @recall-rule NONE
// @recall-expect-absent NOIR_UNCONSTRAINED_WITNESS
//
// Real code: noir_json_parser src/_comparison_tools/lt.nr:16-32
// (also vendored by zkemail-style circuits). `predicate` is an unconstrained
// hint that IS rigorously bound: it is folded into `lt_parameter`, whose sign
// is then pinned by a range assertion. The constraint is a METHOD-form assert
// (`<receiver>.assert_max_bit_size::<240>()`), so the receiver — not an
// argument — is the constrained value.
pub unconstrained fn get_lte_predicate_large(x: Field, y: Field) -> bool {
    x.lt(y) | (x == y)
}

pub fn lte_field_240_bit(x: Field, y: Field) -> bool {
    // Safety: check the comments below
    let predicate = unsafe { get_lte_predicate_large(x, y) };
    let delta = y as Field - x as Field;
    let lt_parameter = 2 * (predicate as Field) * delta - predicate as Field - delta + 1;
    lt_parameter.assert_max_bit_size::<240>();

    predicate
}
