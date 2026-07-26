// @recall-rule NOIR_UNCONSTRAINED_ARRAY_INDEX
// @recall-min-severity medium
// Selector-style lookup with a completely unchecked prover-chosen index: `pos`
// has no bound and the value read back is never pinned, so the prover decides
// which leaf gets published.

fn main(leaves: [Field; 8], pos: u32) -> pub Field {
    let leaf = leaves[pos];
    leaf * 2
}
