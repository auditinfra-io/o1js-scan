// @recall-rule NONE
// @recall-expect-absent NOIR_UNCONSTRAINED_ARRAY_INDEX
// The selection — not the range — is what an equality assertion pins. The
// prover cannot steer `slot`, because a different choice fails `assert_eq`.
// Paired mutation: tp_array_index_pinned.nr drops only the assert_eq line.

fn main(table: [Field; 16], slot: u32, expected: pub Field) {
    let entry = table[slot];
    assert_eq(entry, expected);
}
