// @recall-rule NOIR_UNCONSTRAINED_WITNESS
// @recall-min-severity high
unconstrained fn hint(x: Field) -> Field { x }
fn main(x: Field) -> pub Field {
    let guess = unsafe { hint(x) };
    guess * x
}
