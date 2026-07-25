// @recall-rule NOIR_UNCONSTRAINED_WITNESS
// @recall-min-severity high
//
// MUTATION of fp_bignum_test_helper.nr: the body is IDENTICAL; the only change
// is the context. This fixture carries no `@scan-as`, so it is analyzed under
// its bare basename — not a `*_test.nr` name, not inside `mod test`, and with
// no `#[test]` attribute. In production that hint is genuinely free, so the
// rule must fire. This is what bounds the test-suppression fix: it silences
// test code, not production code.
fn test_sqrt_fail<BN>() where BN: BigNum {
    // Safety: test code
    let qnr_limbs = unsafe { __quadratic_non_residue(&BN::params()) };
    let g: BN = BN::from_limbs(qnr_limbs);
    expect_rejected(g)
}
