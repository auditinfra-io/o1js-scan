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
# Rule 5 — `unsafe {}` missing a `// Safety:` comment
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
