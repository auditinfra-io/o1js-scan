// @recall-rule NONE
// @recall-expect-absent NOIR_UNCONSTRAINED_ARRAY_INDEX
// Distilled from noir_json_parser `json.nr` literal scan: the bound is asserted
// on the PRE-cast value, then the cast result is used as the index.
// Paired mutation: tp_jsonparser_index_bitsize.nr drops only the bit-size line.

fn main(json: [u8; 256], index: Field) -> pub u8 {
    index.assert_max_bit_size::<8>();
    let index_as_u32 = index as u32;
    let first_char = json[index_as_u32];
    first_char
}
