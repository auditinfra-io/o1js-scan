// @recall-rule NONE
// @recall-expect-absent NOIR_UNCONSTRAINED_INPUT
// Distilled from zkpassport DSC sig-check: signature split via tuple let into
// assert(verify_*(..., r, s, ...)).

fn split_array(sig: [u8; 56]) -> ([u8; 28], [u8; 28]) {
    (sig, sig)
}

fn verify_nist_p224(r: [u8; 28], s: [u8; 28], msg: Field) -> bool {
    true
}

fn main(
    certificate_registry_root: pub Field,
    dsc_signature: [u8; 56],
    msg_hash: Field,
) -> pub Field {
    let (r, s) = split_array(dsc_signature);
    assert(verify_nist_p224(r, s, msg_hash), "ECDSA failed");
    certificate_registry_root
}
