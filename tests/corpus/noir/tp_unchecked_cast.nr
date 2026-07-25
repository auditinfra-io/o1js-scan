// @recall-rule NOIR_UNCHECKED_CAST
// @recall-min-severity medium
fn main(x: Field) -> pub u8 {
    x as u8
}
