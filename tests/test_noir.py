"""Tests for the Noir (.nr) circuit soundness analyzer.

Pins the flagship unconstrained-`unsafe`-result rule and its false-positive
guards (direct assert, one-hop assert), the `unsafe`-without-Safety-comment
hygiene rule, source detection, extension dispatch, and provenance.

Fixtures are written against real Noir syntax (the `unsafe { ... }` block that
wraps an unconstrained/oracle/Brillig call and must be re-constrained).
"""

from __future__ import annotations

from o1js_scan import (
    NOIR_ORIGIN_TIER,
    Severity,
    analyze_file,
    analyze_noir_file,
    is_noir_source,
)


def _rules(vulns):
    return sorted(v.rule_id for v in vulns)


# ---------------------------------------------------------------------------
# Source detection
# ---------------------------------------------------------------------------

def test_is_noir_source_by_extension():
    assert is_noir_source("fn main() {}", "circuit.nr")


def test_is_noir_source_rejects_ts():
    assert not is_noir_source("fn main() {}", "x.ts")


def test_is_noir_source_by_content():
    src = "fn main(x: Field) -> pub Field { assert(x != 0); x }"
    assert is_noir_source(src, "")


# ---------------------------------------------------------------------------
# Rule 1 — unconstrained `unsafe {}` result (the marquee rule)
# ---------------------------------------------------------------------------

# The hint result is returned but never re-constrained → prover controls it.
_UNCONSTRAINED = """
unconstrained fn hint(x: Field) -> Field { x }
fn main(x: Field) -> pub Field {
    // Safety: hint is deterministic
    let guess = unsafe { hint(x) };
    guess * x
}
"""

# The hint result IS asserted before use — the correct pattern. Must NOT fire.
_CONSTRAINED = """
unconstrained fn inverse_hint(x: Field) -> Field { x }
fn main(x: Field, y: Field) -> pub Field {
    // Safety: verified below
    let z = unsafe { inverse_hint(x) };
    assert(y * z == x);
    z
}
"""

# The hint flows through an intermediate local that is asserted (one hop).
_CONSTRAINED_ONE_HOP = """
fn main(n: Field, m: Field) {
    // Safety: checked via remainder
    let quotient = unsafe { div_hint(n, m) };
    let remainder = n - quotient * m;
    assert(remainder == 0);
}
"""

# The hint flows through two intermediate locals before being asserted.
_CONSTRAINED_TWO_HOP = """
fn main(n: Field, m: Field) {
    // Safety: checked via ok
    let quotient = unsafe { div_hint(n, m) };
    let remainder = n - quotient * m;
    let ok = remainder == 0;
    assert(ok);
}
"""


def test_unconstrained_unsafe_fires_high():
    v = analyze_noir_file("main.nr", _UNCONSTRAINED)
    fired = [x for x in v if x.rule_id == "NOIR_UNCONSTRAINED_WITNESS"]
    assert fired, _rules(v)
    assert fired[0].severity == Severity.HIGH
    assert fired[0].evidence["witness"] == "guess"
    assert fired[0].evidence["witness_source"] == "unsafe"


def test_constrained_unsafe_does_not_fire():
    v = analyze_noir_file("main.nr", _CONSTRAINED)
    assert "NOIR_UNCONSTRAINED_WITNESS" not in _rules(v)
    assert not [x for x in v if x.severity in (Severity.HIGH, Severity.CRITICAL)]


def test_one_hop_constraint_does_not_fire():
    v = analyze_noir_file("main.nr", _CONSTRAINED_ONE_HOP)
    assert "NOIR_UNCONSTRAINED_WITNESS" not in _rules(v)


def test_two_hop_constraint_does_not_fire():
    v = analyze_noir_file("main.nr", _CONSTRAINED_TWO_HOP)
    assert "NOIR_UNCONSTRAINED_WITNESS" not in _rules(v)


def test_underscore_binding_is_ignored():
    # `_`-prefixed bindings are conventionally intentionally-unused.
    src = """
fn main(x: Field) {
    // Safety: only the sibling path is used
    let (_leaf, path) = unsafe { witness(x) };
    assert(path == x);
}
"""
    assert "NOIR_UNCONSTRAINED_WITNESS" not in _rules(analyze_noir_file("m.nr", src))


def test_confirm_helper_same_file_suppresses():
    # Aztec-nr get_note archetype: unsafe hint passed into confirm_* helper
    # that asserts on the param — must NOT fire HIGH.
    src = """
unconstrained fn view_note() -> Field { 0 }
fn confirm_hinted_note(hinted_note: Field, slot: Field) {
    assert(hinted_note != 0);
    assert(slot != 0);
}
fn get_note(slot: Field) -> Field {
    // Safety: The note is constrained below.
    let hinted_note = unsafe { view_note() };
    confirm_hinted_note(hinted_note, slot)
}
"""
    assert "NOIR_UNCONSTRAINED_WITNESS" not in _rules(analyze_noir_file("note.nr", src))


def test_constrain_call_site_name_suppresses_cross_module_shape():
    # Helper body not in this file — basename `constrain_*` still credits args.
    src = """
fn get_header(block_number: Field) -> Field {
    // Safety: The header is constrained below.
    let header = unsafe { get_block_header_at_internal(block_number) };
    constrain_get_block_header_at_internal(header, block_number);
    header
}
"""
    assert "NOIR_UNCONSTRAINED_WITNESS" not in _rules(analyze_noir_file("hdr.nr", src))


def test_verify_helper_with_field_arg_suppresses():
    # Struct/field args that mention the hint still bind the parent binding.
    src = """
fn verify_collapse_hints(input: Field, collapsed: Field) {
    assert(collapsed == input);
}
fn collapse(input: Field) -> Field {
    // Safety: The hints are verified by verify_collapse_hints.
    let collapsed = unsafe { get_collapse_hints(input) };
    verify_collapse_hints(input, collapsed);
    collapsed
}
"""
    assert "NOIR_UNCONSTRAINED_WITNESS" not in _rules(analyze_noir_file("collapse.nr", src))


def test_documented_random_entropy_suppresses():
    # Intentional privacy entropy — Safety + unsafe { random() } must stay quiet.
    src = """
fn create_note(owner: Field) -> Field {
    // Safety: We use the randomness to preserve privacy; the sender already
    // knows the note pre-image and is trusted not to disclose it.
    let randomness = unsafe { random() };
    owner + randomness
}
"""
    assert "NOIR_UNCONSTRAINED_WITNESS" not in _rules(analyze_noir_file("life.nr", src))


def test_random_without_safety_still_fires():
    # Without Safety, random() is still an unconstrained witness (HIGH).
    src = """
fn create_note(owner: Field) -> Field {
    let randomness = unsafe { random() };
    owner + randomness
}
"""
    fired = [x for x in analyze_noir_file("life.nr", src)
             if x.rule_id == "NOIR_UNCONSTRAINED_WITNESS"]
    assert fired and fired[0].evidence["witness"] == "randomness"


def test_confirm_helper_does_not_suppress_unrelated_free_hint():
    # confirm_* binds only its args — a sibling free unsafe stays HIGH.
    src = """
fn confirm_hinted_note(hinted_note: Field) { assert(hinted_note != 0); }
fn get_note() -> Field {
    // Safety: note constrained; other_hint is NOT.
    let hinted_note = unsafe { view_note() };
    let other_hint = unsafe { view_note() };
    confirm_hinted_note(hinted_note);
    other_hint
}
"""
    fired = [x for x in analyze_noir_file("note.nr", src)
             if x.rule_id == "NOIR_UNCONSTRAINED_WITNESS"]
    assert len(fired) == 1
    assert fired[0].evidence["witness"] == "other_hint"


def test_tuple_let_asserted_flags_bind_membership_witness():
    # Aztec nullifier non-inclusion: witness passed to check_non_membership_*;
    # asserted return flags must bind the witness via tuple let fixpoint / name.
    src = """
fn assert_nullifier_did_not_exist_by(root: Field, nullifier: Field) {
    // Safety: magical values for the proof below.
    let (low_leaf_preimage, witness) = unsafe { get_low_nullifier_membership_witness(root, nullifier) };
    assert(!low_leaf_preimage.is_empty());
    let (non_inclusion, is_valid_low_leaf, low_leaf_exists) = check_non_membership_with_hasher(
        nullifier,
        low_leaf_preimage,
        witness,
        root,
    );
    assert(low_leaf_exists);
    assert(is_valid_low_leaf);
    assert(non_inclusion);
}
"""
    assert "NOIR_UNCONSTRAINED_WITNESS" not in _rules(analyze_noir_file("nullifier.nr", src))


def test_public_data_storage_read_call_binds_witness():
    src = """
fn public_storage_historical_read(root: Field, index: Field) -> Field {
    // Safety: The witness is only used as a magical value for the proof below.
    let witness = unsafe { get_public_data_witness(root, index) };
    public_data_storage_read(
        root,
        index,
        MembershipWitness { leaf_index: witness.index, sibling_path: witness.path },
        witness.leaf_preimage,
    )
}
"""
    assert "NOIR_UNCONSTRAINED_WITNESS" not in _rules(analyze_noir_file("storage.nr", src))


def test_avm_opcode_with_safety_suppresses():
    src = """
fn maybe_msg_sender() -> Field {
    // Safety: AVM opcodes are constrained by the AVM itself
    let maybe_msg_sender = unsafe { avm::sender() };
    maybe_msg_sender
}
"""
    assert "NOIR_UNCONSTRAINED_WITNESS" not in _rules(analyze_noir_file("avm.nr", src))


def test_kernel_deferred_safety_suppresses():
    # Aztec private-context archetype: hint packed for kernel validation.
    src = """
fn in_revertible_phase(counter: Field) -> bool {
    // Safety: Kernel will validate that the claim is correct by validating the
    // expected counters.
    let is_revertible = unsafe { is_execution_in_revertible_phase(counter) };
    is_revertible
}
"""
    assert "NOIR_UNCONSTRAINED_WITNESS" not in _rules(analyze_noir_file("ctx.nr", src))


def test_zkpassport_check_helper_binds_asn1_length():
    src = """
fn check_dg1_sha256(e_content: [u8; 8], e_content_size: u32) {
    assert(e_content_size <= 8);
}
fn main(e_content: [u8; 8]) {
    // Safety: length must be correct for econtent as checked below
    let e_content_size = unsafe { unsafe_get_asn1_element_length(e_content) };
    check_dg1_sha256(e_content, e_content_size);
}
"""
    assert "NOIR_UNCONSTRAINED_WITNESS" not in _rules(analyze_noir_file("z.nr", src))


def test_zkpassport_tuple_let_binds_private_input():
    src = """
fn nullify(salted_dg1: Field, secret: Field) -> (Field, Field) {
    (salted_dg1, secret)
}
fn main(comm_in: pub Field, salted_dg1: Field, secret: Field) -> pub (Field, Field) {
    let (nullifier, nt) = nullify(salted_dg1, secret);
    (nullifier, nt)
}
"""
    assert "NOIR_UNCONSTRAINED_INPUT" not in _rules(analyze_noir_file("z.nr", src))


def test_zkpassport_found_sentinel_suppresses_index_cast():
    src = """
fn check_nationality(dg1: [u8; 3], list: [[u8; 3]; 4]) {
    // Safety: unconstrained index hint
    let country_index = unsafe { unsafe_get_index(list, dg1) };
    assert(country_index != -1);
    let code = list[country_index as u32];
    assert_eq(dg1, code);
}
"""
    assert "NOIR_UNCHECKED_CAST" not in _rules(analyze_noir_file("z.nr", src))


def test_unused_unsafe_hint_is_not_high():
    # Dead ASN.1 length local (facematch codegen) — not a soundness hole.
    src = """
fn main(tbs: [u8; 64]) -> pub Field {
    let intermediate_1_tbs_len = unsafe { unsafe_get_asn1_element_length(tbs) };
    0
}
"""
    assert "NOIR_UNCONSTRAINED_WITNESS" not in _rules(analyze_noir_file("z.nr", src))


def test_generic_safety_alone_does_not_suppress_free_hint():
    # A bare Safety note is NOT enough — must still re-constrain (or match a
    # deferred/entropy/AVM pattern). Keeps the marquee TP honest.
    src = """
fn main(x: Field) -> pub Field {
    // Safety: hint is deterministic
    let guess = unsafe { hint(x) };
    guess * x
}
"""
    assert "NOIR_UNCONSTRAINED_WITNESS" in _rules(analyze_noir_file("main.nr", src))


def test_safety_above_split_let_unsafe_lines_is_adjacent():
    # `let x =` on one line, `unsafe { ... }` on the next — Safety above the let.
    src = """
fn existing_handshake_secrets_or_else() -> Field {
    // Safety: this only selects which source backs the tag. Secrets are
    // constrained against the registry before a constrained tag is emitted.
    let existing =
        unsafe { get_existing_app_siloed_handshake_secrets() };
    existing
}
"""
    assert "NOIR_UNCONSTRAINED_WITNESS" not in _rules(analyze_noir_file("tag.nr", src))
    assert "NOIR_UNSAFE_MISSING_SAFETY" not in _rules(analyze_noir_file("tag.nr", src))


def test_unused_check_result_bare_call_fires_high():
    src = """
fn main(w: Field) {
    // Safety: membership proof discarded
    let witness = unsafe { get_w() };
    check_non_membership_with_hasher(w, witness);
}
"""
    fired = [x for x in analyze_noir_file("m.nr", src)
             if x.rule_id == "NOIR_UNUSED_CHECK_RESULT"]
    assert fired and fired[0].severity == Severity.HIGH


def test_unused_check_result_let_never_asserted_fires_medium():
    src = """
fn main(w: Field) {
    // Safety: ok unused
    let witness = unsafe { get_w() };
    let ok = check_non_membership_with_hasher(w, witness);
}
"""
    fired = [x for x in analyze_noir_file("m.nr", src)
             if x.rule_id == "NOIR_UNUSED_CHECK_RESULT"]
    assert fired and fired[0].severity == Severity.MEDIUM


def test_asserted_check_result_does_not_fire_unused():
    src = """
fn main(w: Field) {
    // Safety: asserted
    let witness = unsafe { get_w() };
    let ok = check_non_membership_with_hasher(w, witness);
    assert(ok);
}
"""
    assert "NOIR_UNUSED_CHECK_RESULT" not in _rules(analyze_noir_file("m.nr", src))


def test_hollow_confirm_helper_does_not_suppress_unsafe():
    src = """
fn confirm_hinted_note(hinted_note: Field) -> Field { hinted_note }
fn get_note() -> Field {
    // Safety: looks constrained but helper is hollow
    let hinted_note = unsafe { view_note() };
    confirm_hinted_note(hinted_note)
}
"""
    assert "NOIR_UNCONSTRAINED_WITNESS" in _rules(analyze_noir_file("note.nr", src))


def test_conditional_constrain_fires_medium():
    src = """
fn main(flag: bool) -> pub Field {
    // Safety: mode-gated
    let hint = unsafe { get_h() };
    if flag {
        constrain_hint(hint);
    }
    hint
}
"""
    fired = [x for x in analyze_noir_file("m.nr", src)
             if x.rule_id == "NOIR_CONDITIONAL_CONSTRAIN"]
    assert fired and fired[0].severity == Severity.MEDIUM


def test_unconditional_constrain_does_not_fire_conditional_rule():
    src = """
fn main() -> pub Field {
    // Safety: constrained below
    let hint = unsafe { get_h() };
    constrain_hint(hint);
    hint
}
"""
    assert "NOIR_CONDITIONAL_CONSTRAIN" not in _rules(analyze_noir_file("m.nr", src))


# ---------------------------------------------------------------------------
# Rule 2 — private input never constrained
# ---------------------------------------------------------------------------
# `secret` is a private witness the circuit never binds (no assert, not output).
_UNCONSTRAINED_INPUT = """
fn main(secret: Field, limit: pub Field) -> pub Field {
    assert(limit < 100);
    limit
}
"""


def test_unconstrained_input_fires_medium():
    v = analyze_noir_file("main.nr", _UNCONSTRAINED_INPUT)
    f = [x for x in v if x.rule_id == "NOIR_UNCONSTRAINED_INPUT"]
    assert f and f[0].severity == Severity.MEDIUM
    assert f[0].evidence["witness"] == "secret"


def test_input_used_in_assert_does_not_fire():
    src = "fn main(x: Field, y: pub Field) { assert(x == y); }"
    assert "NOIR_UNCONSTRAINED_INPUT" not in _rules(analyze_noir_file("m.nr", src))


def test_input_in_public_output_does_not_fire():
    src = "fn main(a: Field, b: Field) -> pub Field { a * b }"
    assert "NOIR_UNCONSTRAINED_INPUT" not in _rules(analyze_noir_file("m.nr", src))


def test_input_bound_via_let_chain_does_not_fire():
    # a -> t -> asserted, through two `let` hops (fixpoint reachability)
    src = """
fn main(a: Field) {
    let t = a + 1;
    let u = t * 2;
    assert(u == 4);
}
"""
    assert "NOIR_UNCONSTRAINED_INPUT" not in _rules(analyze_noir_file("m.nr", src))


def test_input_constrained_by_helper_call_does_not_fire():
    src = """
fn require_equal(candidate: Field, expected: pub Field) {
    assert(candidate == expected);
}

fn main(secret: Field, commitment: pub Field) {
    require_equal(secret, commitment);
}
"""
    assert "NOIR_UNCONSTRAINED_INPUT" not in _rules(analyze_noir_file("m.nr", src))


def test_input_passed_to_unconstraining_helper_still_fires():
    src = """
fn observe(candidate: Field, expected: pub Field) {
    let ignored = candidate + expected;
}

fn main(secret: Field, commitment: pub Field) {
    observe(secret, commitment);
}
"""
    v = analyze_noir_file("m.nr", src)
    f = [x for x in v if x.rule_id == "NOIR_UNCONSTRAINED_INPUT"]
    assert f and f[0].evidence["witness"] == "secret"


def test_public_input_never_flagged():
    src = "fn main(x: pub Field) -> pub Field { x }"
    assert "NOIR_UNCONSTRAINED_INPUT" not in _rules(analyze_noir_file("m.nr", src))


# ---------------------------------------------------------------------------
# Rule 3 — narrowing cast of an unbounded witness (range-check analog)
# ---------------------------------------------------------------------------

def test_unchecked_cast_fires_medium():
    # `x` is a private input cast to u8 with no range assertion on it.
    src = """
fn main(x: Field, out: pub Field) {
    let b = x as u8;
    assert(b == out);
}
"""
    v = analyze_noir_file("m.nr", src)
    f = [c for c in v if c.rule_id == "NOIR_UNCHECKED_CAST"]
    assert f and f[0].severity == Severity.MEDIUM
    assert f[0].evidence["witness"] == "x" and f[0].evidence["cast_to"] == "u8"


def test_unchecked_cast_follows_one_hop_let_assignment():
    src = """
fn main(x: Field, out: pub Field) {
    let y = x;
    let b = y as u8;
    assert(b == out);
}
"""
    v = analyze_noir_file("m.nr", src)
    f = [c for c in v if c.rule_id == "NOIR_UNCHECKED_CAST"]
    assert f and f[0].severity == Severity.MEDIUM
    assert f[0].evidence["witness"] == "y" and f[0].evidence["cast_to"] == "u8"


def test_unchecked_cast_follows_two_hop_derived_value():
    src = """
fn main(x: Field, out: pub Field) {
    let y = x + 1;
    let z = y * 2;
    let b = z as u16;
    assert(b == out);
}
"""
    v = analyze_noir_file("m.nr", src)
    f = [c for c in v if c.rule_id == "NOIR_UNCHECKED_CAST"]
    assert f and f[0].severity == Severity.MEDIUM
    assert f[0].evidence["witness"] == "z" and f[0].evidence["cast_to"] == "u16"

def test_range_bounded_cast_does_not_fire():
    src = """
fn main(x: Field, out: pub Field) {
    assert(x < 256);
    let b = x as u8;
    assert(b == out);
}
"""
    assert "NOIR_UNCHECKED_CAST" not in _rules(analyze_noir_file("m.nr", src))


def test_public_input_cast_does_not_fire():
    # public inputs are not prover-controlled witnesses
    src = "fn main(x: pub Field) -> pub u8 { x as u8 }"
    assert "NOIR_UNCHECKED_CAST" not in _rules(analyze_noir_file("m.nr", src))


def test_cast_of_non_witness_local_does_not_fire():
    # a constant/derived local that is not a tracked witness source
    src = """
fn main(y: pub Field) {
    let k = 42;
    let b = k as u8;
    assert(b as Field == y);
}
"""
    assert "NOIR_UNCHECKED_CAST" not in _rules(analyze_noir_file("m.nr", src))


# ---------------------------------------------------------------------------
# Rule 4 — discarded comparison result (unasserted Bool)
# ---------------------------------------------------------------------------

def test_discarded_equality_statement_fires_high():
    src = """
fn main(x: pub Field, y: pub Field) {
    x == y;
}
"""
    v = analyze_noir_file("m.nr", src)
    f = [c for c in v if c.rule_id == "NOIR_UNASSERTED_BOOL"]
    assert f and f[0].severity == Severity.HIGH


def test_asserted_equality_does_not_fire():
    src = "fn main(x: pub Field, y: pub Field) { assert(x == y); }"
    assert "NOIR_UNASSERTED_BOOL" not in _rules(analyze_noir_file("m.nr", src))


def test_used_comparison_result_does_not_fire():
    src = """
fn main(x: pub Field, y: pub Field) {
    let ok = x == y;
    assert(ok);
}
"""
    assert "NOIR_UNASSERTED_BOOL" not in _rules(analyze_noir_file("m.nr", src))


def test_unused_comparison_let_is_medium():
    src = """
fn main(x: pub Field, y: pub Field) {
    let ok = x == y;
}
"""
    v = analyze_noir_file("m.nr", src)
    f = [c for c in v if c.rule_id == "NOIR_UNASSERTED_BOOL"]
    assert f and f[0].severity == Severity.MEDIUM
    assert f[0].evidence["witness"] == "ok"


def test_comparison_inside_call_does_not_fire():
    # the comparison is an argument, not a discarded statement
    src = """
fn check(b: bool) { assert(b); }
fn main(x: pub Field, y: pub Field) {
    check(x == y);
}
"""
    assert "NOIR_UNASSERTED_BOOL" not in _rules(analyze_noir_file("m.nr", src))


def test_bool_return_expression_does_not_fire():
    src = "fn is_eq(a: Field, b: Field) -> bool { a == b }"
    assert "NOIR_UNASSERTED_BOOL" not in _rules(analyze_noir_file("m.nr", src))


# ---------------------------------------------------------------------------
# Rule 5 — constraint gated by a prover-controlled condition
# ---------------------------------------------------------------------------

def test_conditional_assert_on_witness_bool_fires():
    src = """
fn main(enabled: bool, x: Field, y: pub Field) {
    if enabled {
        assert(x == y);
    }
}
"""
    v = analyze_noir_file("m.nr", src)
    f = [c for c in v if c.rule_id == "NOIR_CONDITIONAL_ASSERT"]
    assert f and f[0].severity == Severity.MEDIUM
    assert f[0].evidence["condition"] == "enabled"
    # not also reported as an unconstrained input
    assert "NOIR_UNCONSTRAINED_INPUT" not in _rules(v)


def test_negated_witness_bool_condition_fires():
    src = """
fn main(skip: bool, x: Field, y: pub Field) {
    if !skip {
        assert(x == y);
    }
}
"""
    assert "NOIR_CONDITIONAL_ASSERT" in _rules(analyze_noir_file("m.nr", src))


def test_public_condition_does_not_fire():
    src = """
fn main(enabled: pub bool, x: Field, y: pub Field) {
    if enabled {
        assert(x == y);
    }
}
"""
    assert "NOIR_CONDITIONAL_ASSERT" not in _rules(analyze_noir_file("m.nr", src))


def test_comparison_guard_does_not_fire():
    # `if x != 0` is a legitimate guard, not a bare witness bool
    src = """
fn main(x: Field, y: pub Field) {
    if x != 0 {
        assert(y == x);
    }
}
"""
    assert "NOIR_CONDITIONAL_ASSERT" not in _rules(analyze_noir_file("m.nr", src))


# ---------------------------------------------------------------------------
# Rule 6 — `unsafe {}` missing a `// Safety:` comment
# ---------------------------------------------------------------------------

def test_missing_safety_comment_is_low():
    src = """
fn main(x: Field) -> pub Field {
    let z = unsafe { hint(x) };
    assert(z == x);
    z
}
"""
    v = analyze_noir_file("m.nr", src)
    f = [x for x in v if x.rule_id == "NOIR_UNSAFE_MISSING_SAFETY"]
    assert f and f[0].severity == Severity.LOW
    # z is asserted, so the unconstrained-witness rule must stay quiet
    assert "NOIR_UNCONSTRAINED_WITNESS" not in _rules(v)


def test_present_safety_comment_no_finding():
    v = analyze_noir_file("main.nr", _CONSTRAINED)
    assert "NOIR_UNSAFE_MISSING_SAFETY" not in _rules(v)


def test_non_adjacent_safety_comment_still_fires():
    src = """
fn main(x: Field) -> pub Field {
    // Safety: this documents a different operation.
    let y = x + 1;
    let z = unsafe { hint(y) };
    assert(z == y);
    z
}
"""
    assert "NOIR_UNSAFE_MISSING_SAFETY" in _rules(analyze_noir_file("m.nr", src))


def test_immediately_preceding_safety_comment_no_finding():
    src = """
fn main(x: Field) -> pub Field {
    // Safety: hint is checked against x below.
    let z = unsafe { hint(x) };
    assert(z == x);
    z
}
"""
    assert "NOIR_UNSAFE_MISSING_SAFETY" not in _rules(analyze_noir_file("m.nr", src))


# ---------------------------------------------------------------------------
# Provenance / dispatch / env
# ---------------------------------------------------------------------------

def test_noir_findings_carry_noir_origin_tier():
    v = analyze_noir_file("main.nr", _UNCONSTRAINED)
    assert v
    assert all(x.origin_tier == NOIR_ORIGIN_TIER for x in v)


def test_analyze_file_dispatches_nr_to_noir():
    v = analyze_file("main.nr", _UNCONSTRAINED)
    assert "NOIR_UNCONSTRAINED_WITNESS" in _rules(v)


def test_env_kill_switch(monkeypatch):
    monkeypatch.setenv("AUDIT_NOIR_LEXER", "0")
    assert analyze_noir_file("main.nr", _UNCONSTRAINED) == []


def test_inline_suppression_applies_to_noir():
    src = """
fn main(x: Field) -> pub Field {
    // Safety: hint is deterministic
    let guess = unsafe { hint(x) };  // o1js-scan-disable-line NOIR_UNCONSTRAINED_WITNESS
    guess * x
}
"""
    assert "NOIR_UNCONSTRAINED_WITNESS" not in _rules(analyze_noir_file("m.nr", src))


# ---------------------------------------------------------------------------
# Test-context suppression (FP class 1) — three detection routes
# ---------------------------------------------------------------------------

# A genuinely unconstrained hint. Fires in production; must be silent in tests.
_FREE_HINT_BODY = """
fn helper_builds_invalid() {
    // Safety: test code
    let bogus = unsafe { __hint() };
    consume(bogus)
}
"""


def test_production_path_still_fires():
    v = analyze_noir_file("src/lib.nr", _FREE_HINT_BODY)
    assert "NOIR_UNCONSTRAINED_WITNESS" in _rules(v)


def test_route_a_test_filename_suppresses():
    for path in ("src/bignum_test.nr", "src/test_helpers.nr",
                 "src/tests/mod.nr", "circuits/test/mod.nr"):
        assert analyze_noir_file(path, _FREE_HINT_BODY) == [], path


def test_route_b_test_attribute_suppresses():
    src = """
#[test]
fn t_free_hint() {
    // Safety: test code
    let bogus = unsafe { __hint() };
    consume(bogus)
}
"""
    assert "NOIR_UNCONSTRAINED_WITNESS" not in _rules(analyze_noir_file("lib.nr", src))


def test_route_b_test_attribute_with_args_suppresses():
    src = """
#[test(should_fail_with = "call to assert_max_bit_size")]
fn t_free_hint() {
    // Safety: test code
    let bogus = unsafe { __hint() };
    consume(bogus)
}
"""
    assert "NOIR_UNCONSTRAINED_WITNESS" not in _rules(analyze_noir_file("lib.nr", src))


def test_route_c_mod_test_is_block_scoped():
    # noir_sort archetype: `mod test {}` at the bottom of a production file.
    # The production fn above it must STILL fire; only the mod is suppressed.
    src = """
fn production_free_hint() {
    // Safety: prod
    let bogus = unsafe { __hint() };
    consume(bogus)
}

mod test {
    fn helper_free_hint() {
        // Safety: test code
        let bogus2 = unsafe { __hint() };
        consume(bogus2)
    }
}
"""
    v = analyze_noir_file("lib.nr", src)
    fired = [x for x in v if x.rule_id == "NOIR_UNCONSTRAINED_WITNESS"]
    assert len(fired) == 1, [x.evidence.get("witness") for x in fired]
    assert fired[0].evidence["witness"] == "bogus"


def test_include_tests_reenables_findings():
    assert "NOIR_UNCONSTRAINED_WITNESS" in _rules(
        analyze_noir_file("src/bignum_test.nr", _FREE_HINT_BODY, include_tests=True)
    )


# ---------------------------------------------------------------------------
# Assert-family seeding (FP classes 2 and 3)
# ---------------------------------------------------------------------------

def test_method_form_assert_constrains_receiver():
    src = """
fn f(x: Field) -> Field {
    // Safety: bound below
    let h = unsafe { hint(x) };
    let combined = h * 2 - x;
    combined.assert_max_bit_size::<240>();
    h
}
"""
    assert "NOIR_UNCONSTRAINED_WITNESS" not in _rules(analyze_noir_file("f.nr", src))


def test_indexed_receiver_credits_base_identifier():
    src = """
fn f(x: Field) -> Field {
    // Safety: bound below
    let chunks = unsafe { split(x) };
    chunks[0].assert_max_bit_size::<8>();
    chunks[0]
}
"""
    assert "NOIR_UNCONSTRAINED_WITNESS" not in _rules(analyze_noir_file("f.nr", src))


def test_suffixed_assert_callback_constrains_args():
    src = """
fn f(input: [Field; 4]) -> [Field; 4] {
    // Safety: bound below
    let sorted = unsafe { qsort(input) };
    for i in 0..3 {
        sortfn_assert(sorted[i], sorted[i + 1]);
    }
    sorted
}
"""
    assert "NOIR_UNCONSTRAINED_WITNESS" not in _rules(analyze_noir_file("f.nr", src))


def test_type_annotated_let_propagates_constraint():
    # `let raw: Field = ...` used not to parse as a binding, orphaning the hint
    # from the assert that binds it (noir_json_parser build_transcript).
    src = """
fn f(j: Field) {
    // Safety: bound below
    let raw_transcript = unsafe { build(j) };
    let raw: Field = raw_transcript[0];
    let diff: Field = raw - expected(j);
    assert(diff == 0);
}
"""
    assert "NOIR_UNCONSTRAINED_WITNESS" not in _rules(analyze_noir_file("f.nr", src))


def test_unrelated_hint_still_fires_alongside_asserted_one():
    # The permissive assert family must not blanket-suppress a sibling free hint.
    src = """
fn f(x: Field) -> Field {
    // Safety: bound below
    let bound = unsafe { hint(x) };
    let free = unsafe { hint(x) };
    bound.assert_max_bit_size::<32>();
    free
}
"""
    fired = [x for x in analyze_noir_file("f.nr", src)
             if x.rule_id == "NOIR_UNCONSTRAINED_WITNESS"]
    assert len(fired) == 1
    assert fired[0].evidence["witness"] == "free"


# ---------------------------------------------------------------------------
# NOIR_UNCONSTRAINED_PUBLIC_INPUT — the dual of the private-witness rule
# ---------------------------------------------------------------------------

def test_unused_public_input_fires_medium():
    # `root` is handed to the verifier but the circuit never reads it.
    src = "fn main(leaf: Field, root: pub Field) { assert(leaf != 0); }"
    v = analyze_noir_file("m.nr", src)
    f = [x for x in v if x.rule_id == "NOIR_UNCONSTRAINED_PUBLIC_INPUT"]
    assert f and f[0].severity == Severity.MEDIUM
    assert f[0].evidence["witness"] == "root"
    assert f[0].evidence["witness_source"] == "public_input"


def test_constrained_public_input_does_not_fire():
    src = "fn main(leaf: Field, root: pub Field) { assert(hash(leaf) == root); }"
    assert "NOIR_UNCONSTRAINED_PUBLIC_INPUT" not in _rules(analyze_noir_file("m.nr", src))


def test_public_input_reaching_output_does_not_fire():
    src = "fn main(a: pub Field) -> pub Field { a * 2 }"
    assert "NOIR_UNCONSTRAINED_PUBLIC_INPUT" not in _rules(analyze_noir_file("m.nr", src))


def test_public_input_bound_through_let_chain_does_not_fire():
    src = """
fn main(x: Field, expected: pub Field) {
    let h = hash(x);
    let ok = h == expected;
    assert(ok);
}
"""
    assert "NOIR_UNCONSTRAINED_PUBLIC_INPUT" not in _rules(analyze_noir_file("m.nr", src))


def test_underscore_public_input_is_ignored():
    # `_`-prefixed marks a deliberately unused binding.
    src = "fn main(leaf: Field, _nonce: pub Field) { assert(leaf != 0); }"
    assert "NOIR_UNCONSTRAINED_PUBLIC_INPUT" not in _rules(analyze_noir_file("m.nr", src))


def test_public_input_rule_does_not_gate_default_ci(tmp_path):
    # MEDIUM by design: a deliberately unused pub input (proof-context binding)
    # is a legitimate idiom, so this rule must not fail the default --fail-on high.
    from o1js_scan.cli import main as cli_main

    p = tmp_path / "m.nr"
    p.write_text("fn main(leaf: Field, nonce: pub Field) { assert(leaf != 0); }")
    assert cli_main([str(p), "--lang", "noir"]) == 0


def test_public_and_private_unconstrained_are_distinct_rules():
    src = "fn main(secret: Field, root: pub Field, seen: pub Field) { assert(seen != 0); }"
    rules = _rules(analyze_noir_file("m.nr", src))
    assert "NOIR_UNCONSTRAINED_INPUT" in rules        # secret
    assert "NOIR_UNCONSTRAINED_PUBLIC_INPUT" in rules  # root


def test_public_input_suppressible_inline():
    src = """
fn main(leaf: Field, nonce: pub Field) {
    // o1js-scan-disable-next-line NOIR_UNCONSTRAINED_PUBLIC_INPUT
    assert(leaf != 0);
}
"""
    # the finding is reported on the `fn main` signature line, so suppress there
    src2 = src.replace(
        "fn main(leaf: Field, nonce: pub Field) {",
        "fn main(leaf: Field, nonce: pub Field) {  "
        "// o1js-scan-disable-line NOIR_UNCONSTRAINED_PUBLIC_INPUT")
    assert "NOIR_UNCONSTRAINED_PUBLIC_INPUT" not in _rules(analyze_noir_file("m.nr", src2))


# ---------------------------------------------------------------------------
# NOIR_VACUOUS_CONSTRAINT — constraints satisfied by construction
# ---------------------------------------------------------------------------

def test_self_comparison_fires_high():
    v = analyze_noir_file("m.nr", "fn main(x: pub Field) { assert(x == x); }")
    f = [c for c in v if c.rule_id == "NOIR_VACUOUS_CONSTRAINT"]
    assert f and f[0].severity == Severity.HIGH
    assert f[0].evidence["expr"] == "x == x"


def test_assert_eq_same_operands_fires_high():
    v = analyze_noir_file("m.nr", "fn main(x: pub Field) { assert_eq(x, x); }")
    f = [c for c in v if c.rule_id == "NOIR_VACUOUS_CONSTRAINT"]
    assert f and f[0].severity == Severity.HIGH


def test_method_form_assert_eq_self_fires():
    v = analyze_noir_file("m.nr", "fn main(x: pub Field) { x.assert_eq(x); }")
    assert "NOIR_VACUOUS_CONSTRAINT" in _rules(v)


def test_constant_true_is_medium():
    src = "fn main(x: pub Field) { assert(true); assert(x != 0); }"
    f = [c for c in analyze_noir_file("m.nr", src)
         if c.rule_id == "NOIR_VACUOUS_CONSTRAINT"]
    assert f and f[0].severity == Severity.MEDIUM


def test_reflexive_ordering_ops_fire():
    for op in (">=", "<="):
        src = f"fn main(x: pub Field) {{ assert(x {op} x); }}"
        assert "NOIR_VACUOUS_CONSTRAINT" in _rules(analyze_noir_file("m.nr", src)), op


def test_message_argument_does_not_hide_vacuity():
    src = 'fn main(x: pub Field) { assert(x == x, "should hold"); }'
    assert "NOIR_VACUOUS_CONSTRAINT" in _rules(analyze_noir_file("m.nr", src))


def test_whitespace_insensitive_comparison():
    src = "fn main(x: pub Field) { assert( x  ==   x ); }"
    assert "NOIR_VACUOUS_CONSTRAINT" in _rules(analyze_noir_file("m.nr", src))


def test_real_comparison_does_not_fire():
    for src in (
        "fn main(a: pub Field, b: pub Field) { assert(a == b); }",
        "fn main(a: pub Field, b: pub Field) { assert_eq(a, b); }",
        "fn main(a: pub Field, b: pub Field) { assert(a >= b); }",
        "fn main(x: pub Field) { assert(hash(x) == commitment(x)); }",
    ):
        assert "NOIR_VACUOUS_CONSTRAINT" not in _rules(analyze_noir_file("m.nr", src)), src


def test_distinct_indices_do_not_fire():
    # arr[i] and arr[j] are different expressions — a real check.
    src = ("fn main(arr: pub [Field; 4], i: pub u32, j: pub u32) "
           "{ assert(arr[i] == arr[j]); }")
    assert "NOIR_VACUOUS_CONSTRAINT" not in _rules(analyze_noir_file("m.nr", src))


def test_always_false_self_comparison_not_flagged():
    # `x != x` is unsatisfiable — a liveness bug, not the silent soundness hole
    # this rule targets. Deliberately out of scope.
    src = "fn main(x: pub Field) { assert(x != x); }"
    assert "NOIR_VACUOUS_CONSTRAINT" not in _rules(analyze_noir_file("m.nr", src))


def test_vacuous_constraint_suppressed_in_test_code():
    src = "fn t(x: Field) { assert(x == x); }"
    assert analyze_noir_file("src/tests/mod.nr", src) == []
