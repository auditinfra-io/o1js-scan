// @recall-rule NONE
// @recall-expect-absent NOIR_UNCHECKED_CAST
// @recall-expect-absent NOIR_UNCONSTRAINED_ARRAY_INDEX
// Distilled from zkpassport country inclusion: unsafe index + assert != -1
// + `as u32` for list lookup, then assert_eq on the looked-up value.

fn check_nationality_inclusion(dg1: [u8; 3], country_list: [[u8; 3]; 8]) {
    // Safety: get the index of the country in the list from an unconstrained function
    let country_index = unsafe { unsafe_get_index(country_list, dg1) };
    assert(country_index != -1, "Country not found in the list");
    let country_code = country_list[country_index as u32];
    assert_eq(dg1, country_code, "Nationality does not match");
}
