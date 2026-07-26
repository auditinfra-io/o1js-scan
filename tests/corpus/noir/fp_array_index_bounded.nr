// @recall-rule NONE
// @recall-expect-absent NOIR_UNCONSTRAINED_ARRAY_INDEX
// Same shape as tp_array_index.nr with a range assertion on `pos` restored.
// The ONLY difference from the tp_ variant is the `assert(pos < 8)` line.
//
// NOTE: a range bound does not by itself make a selector sound — it stops the
// prover leaving the array, not choosing within it. It is suppressed here to
// keep the rule precise; docs/noir_calibration.md records that recall gap.

fn main(leaves: [Field; 8], pos: u32) -> pub Field {
    assert(pos < 8);
    let leaf = leaves[pos];
    leaf * 2
}
