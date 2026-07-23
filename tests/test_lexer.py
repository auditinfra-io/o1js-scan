"""Tests for the o1js (Mina/Kimchi) zkApp soundness lexer.

Pins the four rule families and their false-positive guards, plus a
real-world settlement-contract archetype (the calibration target the
detector was built against).
"""

from __future__ import annotations

from o1js_scan import Severity, analyze_file, is_o1js_source


def _rules(vulns):
    return sorted(v.rule_id for v in vulns)


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

def test_is_o1js_source_positive():
    src = """
    import { SmartContract, Field, method } from 'o1js';
    export class C extends SmartContract {}
    """
    assert is_o1js_source(src, "c.ts")


def test_is_o1js_source_negative_non_o1js():
    assert not is_o1js_source("import { ethers } from 'ethers';", "x.ts")
    assert not is_o1js_source("contract Foo {}", "Foo.sol")


# ---------------------------------------------------------------------------
# Rule 1 — missing state precondition
# ---------------------------------------------------------------------------

_BARE_GET = """
import { SmartContract, Field, State, state, method } from 'o1js';
export class C extends SmartContract {
  @state(Field) root = State<Field>();
  @method async f() {
    const r = this.root.get();
    this.root.set(r.add(1));
  }
}
"""

_SAFE_GET = """
import { SmartContract, Field, State, state, method } from 'o1js';
export class C extends SmartContract {
  @state(Field) root = State<Field>();
  @method async f() {
    const r = this.root.getAndRequireEquals();
    this.root.set(r.add(1));
  }
}
"""


def test_missing_state_precondition_fires_on_bare_get():
    v = analyze_file("c.ts", _BARE_GET)
    assert "O1JS_MISSING_STATE_PRECONDITION" in _rules(v)
    f = next(x for x in v if x.rule_id == "O1JS_MISSING_STATE_PRECONDITION")
    assert f.severity == Severity.HIGH
    assert f.evidence["state_field"] == "root"


def test_getAndRequireEquals_does_not_fire():
    v = analyze_file("c.ts", _SAFE_GET)
    assert "O1JS_MISSING_STATE_PRECONDITION" not in _rules(v)


# ---------------------------------------------------------------------------
# Rule 2 — unconstrained witness flows to effect (the marquee rule)
# ---------------------------------------------------------------------------

_DRAIN = """
import { SmartContract, UInt64, PublicKey, method } from 'o1js';
export class C extends SmartContract {
  @method async pay(to: PublicKey, amount: UInt64) {
    this.send({ to: to, amount: amount });
  }
}
"""

_TRIVIAL = """
import { SmartContract, UInt64, PublicKey, method } from 'o1js';
export class C extends SmartContract {
  @method async pay(to: PublicKey, amount: UInt64) {
    amount.assertGreaterThan(UInt64.zero);
    this.send({ to: to, amount: amount });
  }
}
"""

_SIG_GATED = """
import { SmartContract, UInt64, PublicKey, method } from 'o1js';
export class C extends SmartContract {
  @method async pay(to: PublicKey, amount: UInt64) {
    this.requireSignature();
    this.send({ to: to, amount: amount });
  }
}
"""

_STATE_BOUND = """
import { SmartContract, UInt64, PublicKey, State, state, method } from 'o1js';
export class C extends SmartContract {
  @state(PublicKey) beneficiary = State<PublicKey>();
  @method async pay(to: PublicKey, amount: UInt64) {
    const b = this.beneficiary.getAndRequireEquals();
    b.assertEquals(to);
    amount.assertGreaterThan(UInt64.zero);
    this.send({ to: to, amount: amount });
  }
}
"""


def test_unconstrained_witness_fires_high_on_send():
    v = analyze_file("c.ts", _DRAIN)
    fired = [x for x in v if x.rule_id == "O1JS_UNCONSTRAINED_WITNESS"]
    assert fired, _rules(v)
    assert any(x.severity == Severity.HIGH for x in fired)
    assert any(x.evidence["witness"] == "amount" for x in fired)


def test_findings_carry_o1js_origin_tier():
    from o1js_scan import O1JS_ORIGIN_TIER

    v = analyze_file("c.ts", _DRAIN)
    assert v
    assert all(x.origin_tier == O1JS_ORIGIN_TIER for x in v)


def test_trivially_constrained_witness_is_medium_not_bound():
    v = analyze_file("c.ts", _TRIVIAL)
    amt = [x for x in v if x.evidence.get("witness") == "amount"]
    assert amt and amt[0].rule_id == "O1JS_WITNESS_NOT_BOUND_TO_STATE"


def test_signature_gated_method_suppresses_witness_findings():
    v = analyze_file("c.ts", _SIG_GATED)
    assert "O1JS_UNCONSTRAINED_WITNESS" not in _rules(v)
    assert "O1JS_WITNESS_NOT_BOUND_TO_STATE" not in _rules(v)


def test_witness_bound_to_state_does_not_fire():
    v = analyze_file("c.ts", _STATE_BOUND)
    tos = [x for x in v if x.evidence.get("witness") == "to"]
    assert not tos, [x.rule_id for x in tos]


# ---------------------------------------------------------------------------
# Rule 3 — raw Field used as transfer amount
# ---------------------------------------------------------------------------

_RAW_FIELD_AMOUNT = """
import { SmartContract, Field, PublicKey, method } from 'o1js';
export class C extends SmartContract {
  @method async pay(to: PublicKey, amount: Field) {
    this.send({ to: to, amount: amount });
  }
}
"""


def test_raw_field_amount_flags_missing_range_check():
    v = analyze_file("c.ts", _RAW_FIELD_AMOUNT)
    assert "MissingRangeCheck" in _rules(v)
    f = next(x for x in v if x.rule_id == "MissingRangeCheck")
    assert f.evidence["witness"] == "amount"


# ---------------------------------------------------------------------------
# Rule 4 — weak permissions
# ---------------------------------------------------------------------------

_WEAK_PERMS = """
import { SmartContract, Permissions, method } from 'o1js';
export class C extends SmartContract {
  init() {
    super.init();
    this.account.permissions.set({
      ...Permissions.default(),
      editState: Permissions.proofOrSignature(),
    });
  }
}
"""

_NONE_PERMS = """
import { SmartContract, Permissions } from 'o1js';
export class C extends SmartContract {
  init() {
    this.account.permissions.set({ editState: Permissions.none() });
  }
}
"""


def test_weak_permissions_proof_or_signature():
    v = analyze_file("c.ts", _WEAK_PERMS)
    assert "O1JS_WEAK_PERMISSIONS" in _rules(v)
    f = next(x for x in v if x.rule_id == "O1JS_WEAK_PERMISSIONS")
    assert f.evidence["permission"] == "editState"
    assert f.evidence["value"] == "proofOrSignature"


def test_weak_permissions_none_is_high():
    v = analyze_file("c.ts", _NONE_PERMS)
    f = next(x for x in v if x.rule_id == "O1JS_WEAK_PERMISSIONS")
    assert f.severity == Severity.HIGH


# ---------------------------------------------------------------------------
# Non-o1js / env / smoke
# ---------------------------------------------------------------------------

def test_non_o1js_returns_empty():
    assert analyze_file("x.ts", "export const x = 1;") == []
    assert analyze_file("Foo.sol", "contract Foo {}") == []


def test_env_kill_switch(monkeypatch):
    monkeypatch.setenv("AUDIT_O1JS_LEXER", "0")
    assert analyze_file("c.ts", _DRAIN) == []


# ---------------------------------------------------------------------------
# Robustness — a crafted/malformed file must not hang the CI scanner
# ---------------------------------------------------------------------------

def test_pathological_input_terminates_quickly():
    import time

    # A giant contiguous token run used to drive _FUNC_HEAD_RE / _asserts_on
    # into O(n^2) backtracking (~40s). Bounded quantifiers keep it linear.
    body = "amount.assertGreaterThan(" + "x" * 60000 + ")"
    src = (
        "import { SmartContract, UInt64, PublicKey, method } from 'o1js';\n"
        "export class C extends SmartContract {\n"
        "  @method async pay(to: PublicKey, amount: UInt64) {\n"
        f"    {body}\n"
        "    this.send({ to, amount });\n"
        "  }\n}\n"
    )
    start = time.time()
    analyze_file("c.ts", src)
    assert time.time() - start < 2.0, "analysis of a crafted input hung"


def test_normal_asserts_still_bind_after_bounding():
    # A normal-length equality against on-chain state must still be recognized
    # as a real binding (the quantifier caps are far above real expressions).
    v = analyze_file("Settle.ts", _STATE_BOUND)
    assert not [x for x in v if x.evidence.get("witness") == "to"]


# ---------------------------------------------------------------------------
# CLI — a missing path must fail loudly, not silently pass
# ---------------------------------------------------------------------------

def test_cli_missing_path_errors(capsys):
    from o1js_scan.cli import main

    rc = main(["/no/such/path/xyz"])
    assert rc == 2
    assert "path not found" in capsys.readouterr().err


def test_cli_clean_scan_exits_zero(tmp_path):
    from o1js_scan.cli import main

    (tmp_path / "safe.ts").write_text(_SAFE_GET)
    assert main([str(tmp_path)]) == 0


# ---------------------------------------------------------------------------
# Settlement-contract archetype (real-world calibration target)
# ---------------------------------------------------------------------------

_SETTLEMENT_LIKE = """
import { Field, MerkleMap, Permissions, Poseidon, PublicKey, SmartContract,
  State, Struct, UInt64, method, state } from 'o1js';
export class Settle extends SmartContract {
  @state(PublicKey) beneficiary = State<PublicKey>();
  @state(Field) serviceCommitment = State<Field>();
  @state(Field) settlementRoot = State<Field>();
  init() {
    super.init();
    this.account.permissions.set({
      ...Permissions.default(),
      editState: Permissions.proofOrSignature(),
    });
  }
  @method async configure(beneficiary: PublicKey, commitment: Field) {
    this.requireSignature();
    this.beneficiary.set(beneficiary);
    this.serviceCommitment.set(commitment);
  }
  @method async settleExact(payer: PublicKey, beneficiary: PublicKey, amountNanomina: UInt64) {
    const configured = this.beneficiary.getAndRequireEquals();
    configured.assertEquals(beneficiary);
    amountNanomina.assertGreaterThan(UInt64.zero);
    this.send({ to: beneficiary, amount: amountNanomina });
  }
}
"""


def test_settlement_archetype_findings():
    v = analyze_file("Settle.ts", _SETTLEMENT_LIKE)
    rules = _rules(v)
    # configure is requireSignature-gated → its witnesses suppressed
    assert not any(x.function == "configure" for x in v)
    # settleExact: beneficiary bound to state (suppressed), amount only trivial
    amt = [x for x in v if x.evidence.get("witness") == "amountNanomina"]
    assert amt and amt[0].rule_id == "O1JS_WITNESS_NOT_BOUND_TO_STATE"
    ben = [x for x in v if x.evidence.get("witness") == "beneficiary"]
    assert not ben, "beneficiary is bound via assertEquals to on-chain state"
    # weak permissions present
    assert "O1JS_WEAK_PERMISSIONS" in rules
