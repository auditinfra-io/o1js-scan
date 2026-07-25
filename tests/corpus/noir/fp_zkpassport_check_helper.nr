// @recall-rule NONE
// @recall-expect-absent NOIR_UNCONSTRAINED_WITNESS
// Distilled from zkpassport/circuits integrity mains: ASN.1 length hint
// passed into check_* helpers that assert on the size.

fn check_dg1_sha256(dg1: [u8; 93], e_content: [u8; 700], e_content_size: u32) {
    assert(e_content_size <= 700);
    let h = dg1[0];
    assert(e_content[0] == h);
}

fn main(comm_in: pub Field, e_content: [u8; 700], dg1: [u8; 93]) -> pub Field {
    // Safety: This is safe because the length must be correct for econtent to hash to
    // the expected digest in signed attributes as checked below in check_signed_attributes_sha256
    let e_content_size = unsafe { unsafe_get_asn1_element_length(e_content) };
    check_dg1_sha256(dg1, e_content, e_content_size);
    comm_in
}
