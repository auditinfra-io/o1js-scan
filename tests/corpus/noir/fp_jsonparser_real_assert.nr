// @recall-rule NONE
// @recall-expect-absent NOIR_VACUOUS_CONSTRAINT
//
// Real code, trimmed: noir_json_parser@695b25ad
// src/_string_tools/slice_packed_field.nr — the reconstruction check at the end
// of `slice_field`. Both operands differ, so the constraint does real work and
// the rule must stay quiet. Representative of 4,911 assert call sites across the
// corpus, none of which fire.
pub fn slice_field(f: Field, num_bytes: u32) -> (Field, Field) {
    // Safety: we check the bit lengths of the chunks with assertions later
    let chunks = unsafe { __slice_field(f, num_bytes) };
    chunks[0].assert_max_bit_size::<8>();
    chunks[1].assert_max_bit_size::<16>();

    let head = chunks[1] * path_multipliers_chunk1[num_bytes];
    let tail = chunks[0] * tail_path_multipliers_chunk0[num_bytes];

    let total = tail + head * BYTE_SHIFT[num_bytes];
    assert(total == f);

    (head, tail)
}
