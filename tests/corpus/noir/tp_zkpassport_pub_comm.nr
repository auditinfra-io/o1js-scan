// @recall-rule NOIR_UNCONSTRAINED_PUBLIC_INPUT
// @recall-min-severity medium
//
// MUTATION of fp_zkpassport_pub_comm.nr: the ONLY change is deleting the two
// lines that compute and assert the commitment, leaving `comm_in` declared as a
// public input but never read. The verifier still supplies `comm_in` and still
// believes the statement is about it, while the circuit ignores it entirely —
// the dual of an under-constrained private witness.
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

    calculate_comm_out(salt_in, salted_dg1, signed_attributes)
}
