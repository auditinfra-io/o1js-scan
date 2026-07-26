// @recall-rule NOIR_UNCONSTRAINED_ARRAY_INDEX
// @recall-min-severity medium
// Mutation of fp_array_index_pinned.nr: the `assert_eq(entry, expected)` that
// pinned the selection is deleted, and nothing else changes. Nothing now stops
// the prover choosing any slot, so the rule must fire.

fn main(table: [Field; 16], slot: u32, expected: pub Field) {
    let entry = table[slot];
}
