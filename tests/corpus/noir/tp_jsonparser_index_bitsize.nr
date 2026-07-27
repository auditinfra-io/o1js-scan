// @recall-rule NOIR_UNCONSTRAINED_ARRAY_INDEX
// @recall-min-severity medium
// Mutation of fp_jsonparser_index_bitsize.nr: the `assert_max_bit_size::<8>()`
// on the pre-cast value is deleted and nothing else changes. The index is now
// wholly unchecked, so the rule must fire.

fn main(json: [u8; 256], index: Field) -> pub u8 {
    let index_as_u32 = index as u32;
    let first_char = json[index_as_u32];
    first_char
}
