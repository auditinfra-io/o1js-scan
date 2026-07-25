// @recall-rule NONE
// @recall-expect-absent NOIR_UNCONSTRAINED_WITNESS
// @scan-as src/tests/bignum_test.nr
//
// Test-context suppression, route (a): the *filename* (`*_test.nr`, and a
// `tests/` path segment) marks this as test code. Modelled on noir-bignum
// src/tests/bignum_test.nr — note the helper is NOT itself `#[test]`-decorated
// (it is a generic helper called from `#[test]` wrappers), so filename handling
// is what catches it.
//
// NB on provenance: the verbatim noir-bignum `test_sqrt_fail` body could not be
// used here. Its hint chain (`qnr_limbs` -> `g` -> `c` -> `assert(c.is_none())`)
// is a genuine constraint, so it is silent in production too and cannot
// discriminate this fix. The body below keeps the shape that matters — a test
// deliberately building an invalid value from a hint — while being genuinely
// unconstrained, so the tp_ twin really does fire. See docs/noir_calibration.md.
fn test_sqrt_fail<BN>() where BN: BigNum {
    // Safety: test code
    let qnr_limbs = unsafe { __quadratic_non_residue(&BN::params()) };
    let g: BN = BN::from_limbs(qnr_limbs);
    expect_rejected(g)
}
