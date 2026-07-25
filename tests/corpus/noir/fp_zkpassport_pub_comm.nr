// @recall-rule NONE
// @recall-expect-absent NOIR_UNCONSTRAINED_PUBLIC_INPUT
//
// Real code, trimmed: zkpassport/circuits@d3a75ac
// src/noir/bin/data-check/integrity/sa_sha384/dg_sha1/src/main.nr
// The public input `comm_in` IS used — it is fed into the commitment check —
// so the proof genuinely binds it and the rule must stay quiet. Representative
// of ~780 circuit entry points in that tree, none of which fire.
fn main(
    comm_in: pub Field,
    salt_in: Field,
    salted_dg1: SaltedValue<DG1Data>,
    signed_attributes: SignedAttrsData,
    e_content: EContentData,
) -> pub Field {
    // Safety: length must be correct for econtent to hash to the expected digest
    let e_content_size = unsafe { utils::unsafe_get_asn1_element_length(e_content) };
    check_dg1_sha1(salted_dg1.value, e_content, e_content_size);

    let calculated_comm_in = calculate_integrity_check_commitment(salt_in, salted_dg1);
    assert(calculated_comm_in == comm_in, "Invalid commitment");

    calculate_comm_out(salt_in, salted_dg1, signed_attributes)
}
