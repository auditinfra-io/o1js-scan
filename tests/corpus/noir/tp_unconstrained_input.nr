// @recall-rule NOIR_UNCONSTRAINED_INPUT
// @recall-min-severity medium
fn main(secret: Field, limit: pub Field) -> pub Field {
    assert(limit < 100);
    limit
}
