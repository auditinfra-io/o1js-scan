// @recall-rule NONE
// @recall-expect-absent NOIR_UNCONSTRAINED_INPUT
// Distilled from zkpassport inclusion-check mains: private inputs only reach
// the public return via `let (a,b,c) = nullify(...)` destructuring.

fn nullify(
    comm_in: Field,
    salted_dg1: Field,
    nullifier_secret: Field,
) -> (Field, Field, Field) {
    (comm_in + salted_dg1, nullifier_secret, 0)
}

fn main(
    comm_in: pub Field,
    salted_dg1: Field,
    nullifier_secret: Field,
) -> pub (Field, Field, Field) {
    let (nullifier, nullifier_type, oprf_pk_hash) = nullify(
        comm_in,
        salted_dg1,
        nullifier_secret,
    );
    (nullifier_type, nullifier, oprf_pk_hash)
}
