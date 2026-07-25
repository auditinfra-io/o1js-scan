// @recall-rule NOIR_VACUOUS_CONSTRAINT
// @recall-min-severity high
//
// MUTATION of fp_jsonparser_real_assert.nr: the ONLY change is `assert(total == f)`
// -> `assert(total == total)`. The reconstruction is no longer checked against
// the input at all, but the line still reads as a constraint — which is exactly
// why a vacuous constraint is more dangerous than a missing one.
pub fn slice_field(f: Field, num_bytes: u32) -> (Field, Field) {
    // Safety: we check the bit lengths of the chunks with assertions later
    let chunks = unsafe { __slice_field(f, num_bytes) };
    chunks[0].assert_max_bit_size::<8>();
    chunks[1].assert_max_bit_size::<16>();

    let head = chunks[1] * path_multipliers_chunk1[num_bytes];
    let tail = chunks[0] * tail_path_multipliers_chunk0[num_bytes];

    let total = tail + head * BYTE_SHIFT[num_bytes];
    assert(total == total);

    (head, tail)
}
