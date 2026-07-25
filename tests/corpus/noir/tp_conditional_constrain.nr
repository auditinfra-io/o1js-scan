// @recall-rule NOIR_CONDITIONAL_CONSTRAIN
// @recall-min-severity medium
fn main(flag: bool) -> pub Field {
    // Safety: mode-gated constrain
    let hint = unsafe { get_h() };
    if flag {
        constrain_hint(hint);
    }
    hint
}
