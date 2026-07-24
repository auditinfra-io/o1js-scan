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
# Rule 2c — unconstrained `Provable.witness` local (the Circom-signal analog)
# ---------------------------------------------------------------------------

# A fresh Provable.witness result flows straight into a send amount with no
# in-circuit assertion → prover-controlled, HIGH.
_PROVABLE_WITNESS_DRAIN = """
import { SmartContract, UInt64, PublicKey, Provable, method } from 'o1js';
export class Rewards extends SmartContract {
  @method async claim(to: PublicKey) {
    const payout = Provable.witness(UInt64, () => this.offchainReward());
    this.send({ to: to, amount: payout });
  }
}
"""

# Same shape, but the witness is re-derived and asserted in-circuit before use
# — the CORRECT witness pattern. Must NOT fire.
_PROVABLE_WITNESS_CHECKED = """
import { SmartContract, UInt64, PublicKey, Provable, method } from 'o1js';
export class Rewards extends SmartContract {
  @method async claim(to: PublicKey, base: UInt64) {
    const payout = Provable.witness(UInt64, () => base.mul(2).toConstant());
    payout.assertEquals(base.mul(2));
    this.send({ to: to, amount: payout });
  }
}
"""


def test_provable_witness_unconstrained_fires_high_on_send():
    v = analyze_file("Rewards.ts", _PROVABLE_WITNESS_DRAIN)
    fired = [x for x in v if x.rule_id == "O1JS_UNCONSTRAINED_PROVABLE_WITNESS"]
    assert fired, _rules(v)
    assert fired[0].severity == Severity.HIGH
    assert fired[0].evidence["witness"] == "payout"
    assert fired[0].evidence["witness_source"] == "Provable.witness"


def test_provable_witness_reasserted_does_not_fire():
    v = analyze_file("Rewards.ts", _PROVABLE_WITNESS_CHECKED)
    assert "O1JS_UNCONSTRAINED_PROVABLE_WITNESS" not in _rules(v)
    # correct code carries no high/critical finding
    assert not [x for x in v if x.severity in (Severity.HIGH, Severity.CRITICAL)]


# ---------------------------------------------------------------------------
# Rule 3b — stale Merkle root (witness root not bound to on-chain state)
# ---------------------------------------------------------------------------

# Recomputes a root from the prover's witness and overwrites on-chain root
# WITHOUT ever binding a recomputed root to the current root → prover can pass
# a witness for any tree. HIGH.
_STALE_MERKLE = """
import { SmartContract, Field, State, state, MerkleMapWitness, method } from 'o1js';
export class Registry extends SmartContract {
  @state(Field) root = State<Field>();
  @method async set(witness: MerkleMapWitness, value: Field) {
    const [newRoot, key] = witness.computeRootAndKey(value);
    this.root.set(newRoot);
  }
}
"""

# Correct update: binds the recomputed OLD root to the current on-chain root
# before setting the new root. Must NOT fire (even though newRoot is unasserted).
_SAFE_MERKLE = """
import { SmartContract, Field, State, state, MerkleMapWitness, method } from 'o1js';
export class Registry extends SmartContract {
  @state(Field) root = State<Field>();
  @method async update(witness: MerkleMapWitness, oldValue: Field, newValue: Field) {
    const current = this.root.getAndRequireEquals();
    const [rootBefore, key] = witness.computeRootAndKey(oldValue);
    rootBefore.assertEquals(current);
    const [rootAfter, key2] = witness.computeRootAndKey(newValue);
    this.root.set(rootAfter);
  }
}
"""

# Membership check via MerkleWitness.calculateRoot bound with requireEquals.
_SAFE_MERKLE_REQUIRE = """
import { SmartContract, Field, State, state, MerkleWitness, method } from 'o1js';
export class Registry extends SmartContract {
  @state(Field) root = State<Field>();
  @method async prove(witness: MerkleWitness, leaf: Field) {
    const computed = witness.calculateRoot(leaf);
    this.root.requireEquals(computed);
  }
}
"""


def test_stale_merkle_root_fires_high():
    v = analyze_file("Registry.ts", _STALE_MERKLE)
    fired = [x for x in v if x.rule_id == "O1JS_STALE_MERKLE_ROOT"]
    assert fired, _rules(v)
    assert fired[0].severity == Severity.HIGH
    assert fired[0].evidence["witness_recv"] == "witness"
    assert fired[0].evidence["api"] == "computeRootAndKey"


def test_safe_merkle_update_does_not_fire():
    v = analyze_file("Registry.ts", _SAFE_MERKLE)
    assert "O1JS_STALE_MERKLE_ROOT" not in _rules(v)
    assert not [x for x in v if x.severity in (Severity.HIGH, Severity.CRITICAL)]


def test_safe_merkle_require_equals_does_not_fire():
    v = analyze_file("Registry.ts", _SAFE_MERKLE_REQUIRE)
    assert "O1JS_STALE_MERKLE_ROOT" not in _rules(v)


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
# False-positive fixes — recipient witness + state-derived comparisons
# ---------------------------------------------------------------------------

_SAFE_VAULT = """
import { SmartContract, UInt64, PublicKey, State, state, method } from 'o1js';
export class SafeVault extends SmartContract {
  @state(UInt64) bal = State<UInt64>();
  @method async withdraw(to: PublicKey, amount: UInt64) {
    const b = this.bal.getAndRequireEquals();
    amount.assertLessThanOrEqual(b);
    this.send({ to: to, amount: amount });
    this.bal.set(b.sub(amount));
  }
}
"""

_SAFE_VAULT_NO_CHECK = """
import { SmartContract, UInt64, PublicKey, State, state, method } from 'o1js';
export class SafeVault extends SmartContract {
  @state(UInt64) bal = State<UInt64>();
  @method async withdraw(to: PublicKey, amount: UInt64) {
    const b = this.bal.getAndRequireEquals();
    this.send({ to: to, amount: amount });
    this.bal.set(b.sub(amount));
  }
}
"""

_SAFE_VAULT_CHAINED = """
import { SmartContract, UInt64, PublicKey, State, state, method } from 'o1js';
export class SafeVault extends SmartContract {
  @state(UInt64) bal = State<UInt64>();
  @method async withdraw(to: PublicKey, amount: UInt64) {
    const b = this.bal.getAndRequireEquals();
    amount.lessThanOrEqual(b).assertTrue();
    this.send({ to: to, amount: amount });
    this.bal.set(b.sub(amount));
  }
}
"""

_SAFE_VAULT_CONST = """
import { SmartContract, UInt64, PublicKey, State, state, method } from 'o1js';
export class SafeVault extends SmartContract {
  @state(UInt64) bal = State<UInt64>();
  @method async withdraw(to: PublicKey, amount: UInt64) {
    const b = this.bal.getAndRequireEquals();
    amount.assertLessThanOrEqual(UInt64.from(100));
    this.send({ to: to, amount: amount });
    this.bal.set(b.sub(amount));
  }
}
"""

_FIXED_TREASURY = """
import { SmartContract, UInt64, PublicKey, State, state, method } from 'o1js';
export class Payout extends SmartContract {
  @state(UInt64) bal = State<UInt64>();
  @state(PublicKey) treasury = State<PublicKey>();
  @method async payout(to: PublicKey, amount: UInt64) {
    const t = this.treasury.getAndRequireEquals();
    t.assertEquals(to);
    const b = this.bal.getAndRequireEquals();
    amount.assertLessThanOrEqual(b);
    this.send({ to: to, amount: amount });
  }
}
"""


def test_safe_vault_no_high_and_recipient_is_low():
    v = analyze_file("SafeVault.ts", _SAFE_VAULT)
    # No high/critical findings on correct code.
    assert not [x for x in v if x.severity in (Severity.HIGH, Severity.CRITICAL)]
    # `amount` is bound to on-chain state -> no finding at all.
    assert not [x for x in v if x.evidence.get("witness") == "amount"]
    # `to` is a prover-chosen recipient -> LOW O1JS_UNCONSTRAINED_RECIPIENT.
    tos = [x for x in v if x.evidence.get("witness") == "to"]
    assert tos and all(x.rule_id == "O1JS_UNCONSTRAINED_RECIPIENT" for x in tos)
    assert all(x.severity == Severity.LOW for x in tos)


def test_recipient_low_does_not_trip_cli_exit_gate(tmp_path):
    from o1js_scan.cli import main

    (tmp_path / "SafeVault.ts").write_text(_SAFE_VAULT)
    assert main([str(tmp_path)]) == 0


def test_amount_fires_high_when_bound_check_removed():
    v = analyze_file("SafeVault.ts", _SAFE_VAULT_NO_CHECK)
    amt = [x for x in v if x.evidence.get("witness") == "amount"]
    assert amt and amt[0].rule_id == "O1JS_UNCONSTRAINED_WITNESS"
    assert amt[0].severity == Severity.HIGH


def test_chained_comparison_binds_amount():
    v = analyze_file("SafeVault.ts", _SAFE_VAULT_CHAINED)
    assert not [x for x in v if x.evidence.get("witness") == "amount"]


def test_comparison_against_constant_is_medium_not_bound():
    v = analyze_file("SafeVault.ts", _SAFE_VAULT_CONST)
    amt = [x for x in v if x.evidence.get("witness") == "amount"]
    assert amt and amt[0].rule_id == "O1JS_WITNESS_NOT_BOUND_TO_STATE"
    assert amt[0].severity == Severity.MEDIUM


def test_state_bound_recipient_has_no_recipient_finding():
    v = analyze_file("Payout.ts", _FIXED_TREASURY)
    assert not [x for x in v if x.rule_id == "O1JS_UNCONSTRAINED_RECIPIENT"]
    assert not [x for x in v if x.evidence.get("witness") == "to"]


def test_severity_json_casing_is_lowercase():
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                Severity.LOW, Severity.INFO):
        assert sev.value == sev.value.lower()
    # critical specifically must serialize lowercase through to_dict()
    from o1js_scan import Vulnerability

    d = Vulnerability(pattern_name="X", severity=Severity.CRITICAL).to_dict()
    assert d["severity"] == "critical"


# ---------------------------------------------------------------------------
# o1js 2.x compatibility — the authoring APIs the detector matches are stable
# across 1.x/2.x. These pin idiomatic 2.x forms (`@method.returns(...)`,
# `this.sender.getAndRequireSignature()`, `this.sender.getUnconstrained()`).
# ---------------------------------------------------------------------------

# 2.x removed `this.sender`; owner auth is now `this.sender.getAndRequireSignature()`.
# That still gates the method, so its prover-supplied args stay suppressed.
_O1JS_2X_SENDER_AUTH = """
import { SmartContract, UInt64, PublicKey, method } from 'o1js';
export class Wallet extends SmartContract {
  @method async pay(to: PublicKey, amount: UInt64) {
    const owner = this.sender.getAndRequireSignature();
    this.send({ to: to, amount: amount });
  }
}
"""

# An UNGATED 2.x method (uses the non-proving `getUnconstrained()` and the 2.x
# `@method.returns(...)` return form) with an unbound amount must still fire.
_O1JS_2X_UNGATED_DRAIN = """
import { SmartContract, UInt64, State, state, method } from 'o1js';
export class Vault extends SmartContract {
  @state(UInt64) total = State<UInt64>();
  @method.returns(UInt64) async withdraw(amount: UInt64): Promise<UInt64> {
    const t = this.total.getAndRequireEquals();
    this.send({ to: this.sender.getUnconstrained(), amount: amount });
    this.total.set(t.sub(amount));
    return amount;
  }
}
"""


def test_o1js_2x_sender_auth_gates_method():
    # `this.sender.getAndRequireSignature()` is the 2.x owner-auth idiom and
    # must be recognized as signature-gating, suppressing witness findings.
    v = analyze_file("Wallet.ts", _O1JS_2X_SENDER_AUTH)
    assert "O1JS_UNCONSTRAINED_WITNESS" not in _rules(v)
    assert "O1JS_WITNESS_NOT_BOUND_TO_STATE" not in _rules(v)
    assert "O1JS_UNCONSTRAINED_RECIPIENT" not in _rules(v)


def test_o1js_2x_ungated_method_still_detects():
    # Proves 2.x support is real detection, not blanket-quiet: an ungated
    # `@method.returns(...)` method with an unbound amount fires HIGH.
    v = analyze_file("Vault.ts", _O1JS_2X_UNGATED_DRAIN)
    amt = [x for x in v if x.evidence.get("witness") == "amount"]
    assert amt and amt[0].rule_id == "O1JS_UNCONSTRAINED_WITNESS"
    assert amt[0].severity == Severity.HIGH


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


# ---------------------------------------------------------------------------
# Inline suppressions
# ---------------------------------------------------------------------------

_SUPPRESS_NEXT_LINE = """
import { SmartContract, UInt64, PublicKey, method } from 'o1js';
export class C extends SmartContract {
  @method async pay(to: PublicKey, amount: UInt64) {
    // o1js-scan-disable-next-line O1JS_UNCONSTRAINED_WITNESS
    this.send({ to: to, amount: amount });
  }
}
"""

_SUPPRESS_SAME_LINE_ALL = """
import { SmartContract, UInt64, PublicKey, method } from 'o1js';
export class C extends SmartContract {
  @method async pay(to: PublicKey, amount: UInt64) {
    this.send({ to: to, amount: amount });  // o1js-scan-disable-line
  }
}
"""


def test_suppress_next_line_only_named_rule():
    v = analyze_file("c.ts", _SUPPRESS_NEXT_LINE)
    # the named rule is gone; other findings on the line remain
    assert "O1JS_UNCONSTRAINED_WITNESS" not in _rules(v)
    assert "O1JS_UNCONSTRAINED_RECIPIENT" in _rules(v)


def test_suppress_same_line_bare_directive_silences_all():
    v = analyze_file("c.ts", _SUPPRESS_SAME_LINE_ALL)
    assert v == []


def test_suppression_does_not_leak_to_other_lines():
    # a disable on the send line must not silence an unrelated finding elsewhere
    v = analyze_file("c.ts", _SUPPRESS_NEXT_LINE)
    assert v, "unrelated recipient finding should survive"


# ---------------------------------------------------------------------------
# CLI — --fail-on threshold and --version
# ---------------------------------------------------------------------------

_HIGH_FINDING = """
import { SmartContract, UInt64, PublicKey, method } from 'o1js';
export class C extends SmartContract {
  @method async pay(to: PublicKey, amount: UInt64) {
    this.send({ to: to, amount: amount });
  }
}
"""


def _write(tmp_path, name, src):
    p = tmp_path / name
    p.write_text(src)
    return str(p)


def test_fail_on_default_high_exits_1(tmp_path):
    from o1js_scan.cli import main

    assert main([_write(tmp_path, "C.ts", _HIGH_FINDING)]) == 1


def test_fail_on_none_never_fails(tmp_path):
    from o1js_scan.cli import main

    assert main([_write(tmp_path, "C.ts", _HIGH_FINDING), "--fail-on", "none"]) == 0


def test_fail_on_critical_ignores_high(tmp_path):
    from o1js_scan.cli import main

    assert main([_write(tmp_path, "C.ts", _HIGH_FINDING), "--fail-on", "critical"]) == 0


def test_fail_on_medium_catches_high(tmp_path):
    from o1js_scan.cli import main

    assert main([_write(tmp_path, "C.ts", _HIGH_FINDING), "--fail-on", "medium"]) == 1


def test_version_flag_prints_and_exits_zero(capsys):
    import pytest as _pytest
    from o1js_scan import __version__
    from o1js_scan.cli import main

    with _pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_summary_line_reports_counts(tmp_path, capsys):
    from o1js_scan.cli import main

    main([_write(tmp_path, "C.ts", _HIGH_FINDING)])
    err = capsys.readouterr().err
    assert "finding(s)" in err and "1 high" in err


# ---------------------------------------------------------------------------
# FP class 1 — depth-1 cross-method helper binding (Response.ts shape)
# ---------------------------------------------------------------------------

# Binding lives in an undecorated helper; @method only calls it then recomputes.
_HELPER_BOUND_MERKLE = """
import { SmartContract, Field, State, state, MerkleWitness, method } from 'o1js';
export class Response extends SmartContract {
  @state(Field) finalizedDRoot = State<Field>();
  @method async finalize(finalizedDWitness: MerkleWitness, value: Field) {
    this.verifyFinalizedD(value, finalizedDWitness);
    let nextFinalizedDRoot = finalizedDWitness.calculateRoot(value);
    this.finalizedDRoot.set(nextFinalizedDRoot);
  }
  verifyFinalizedD(value: Field, witness: MerkleWitness) {
    this.finalizedDRoot.getAndRequireEquals().assertEquals(witness.calculateRoot(value));
  }
}
"""

# Same contract with the helper call DELETED → HIGH must fire again.
_HELPER_BOUND_MERKLE_NO_CALL = """
import { SmartContract, Field, State, state, MerkleWitness, method } from 'o1js';
export class Response extends SmartContract {
  @state(Field) finalizedDRoot = State<Field>();
  @method async finalize(finalizedDWitness: MerkleWitness, value: Field) {
    let nextFinalizedDRoot = finalizedDWitness.calculateRoot(value);
    this.finalizedDRoot.set(nextFinalizedDRoot);
  }
  verifyFinalizedD(value: Field, witness: MerkleWitness) {
    this.finalizedDRoot.getAndRequireEquals().assertEquals(witness.calculateRoot(value));
  }
}
"""

# Helper exists but does NO state binding (no-op) → finding still fires.
_HELPER_NOOP_MERKLE = """
import { SmartContract, Field, State, state, MerkleWitness, method } from 'o1js';
export class Response extends SmartContract {
  @state(Field) finalizedDRoot = State<Field>();
  @method async finalize(finalizedDWitness: MerkleWitness, value: Field) {
    this.verifyFinalizedD(value, finalizedDWitness);
    let nextFinalizedDRoot = finalizedDWitness.calculateRoot(value);
    this.finalizedDRoot.set(nextFinalizedDRoot);
  }
  verifyFinalizedD(value: Field, witness: MerkleWitness) {
    // intentionally no state binding
  }
}
"""

# Witness passed at an index the helper does NOT bind → finding still fires.
# Helper binds param 0 (`a`), but the merkle witness is at call index 1.
_HELPER_WRONG_INDEX_MERKLE = """
import { SmartContract, Field, State, state, MerkleWitness, method } from 'o1js';
export class Response extends SmartContract {
  @state(Field) finalizedDRoot = State<Field>();
  @state(Field) other = State<Field>();
  @method async finalize(unrelated: Field, finalizedDWitness: MerkleWitness, value: Field) {
    this.verifySomething(unrelated, finalizedDWitness);
    let nextFinalizedDRoot = finalizedDWitness.calculateRoot(value);
    this.finalizedDRoot.set(nextFinalizedDRoot);
  }
  verifySomething(a: Field, witness: MerkleWitness) {
    // binds ONLY `a` (index 0), NOT `witness` (index 1)
    this.other.getAndRequireEquals().assertEquals(a);
  }
}
"""


def test_helper_bound_merkle_suppresses_stale_root():
    v = analyze_file("Response.ts", _HELPER_BOUND_MERKLE)
    assert "O1JS_STALE_MERKLE_ROOT" not in _rules(v), _rules(v)


def test_helper_bound_merkle_without_call_fires_high():
    # Discrimination canary: deleting the helper call must restore the finding.
    v = analyze_file("Response.ts", _HELPER_BOUND_MERKLE_NO_CALL)
    fired = [x for x in v if x.rule_id == "O1JS_STALE_MERKLE_ROOT"]
    assert fired and fired[0].severity == Severity.HIGH


def test_helper_noop_does_not_launder_witness():
    v = analyze_file("Response.ts", _HELPER_NOOP_MERKLE)
    assert "O1JS_STALE_MERKLE_ROOT" in _rules(v)


def test_helper_wrong_param_index_does_not_bind():
    v = analyze_file("Response.ts", _HELPER_WRONG_INDEX_MERKLE)
    assert "O1JS_STALE_MERKLE_ROOT" in _rules(v)


# ---------------------------------------------------------------------------
# FP class 2 — proof-typed arguments + O1JS_UNVERIFIED_PROOF
# ---------------------------------------------------------------------------

_VERIFIED_PROOF = """
import { SmartContract, Field, State, state, method } from 'o1js';
class ExactGeolocationMetadataCircuitProof {}
export class ExactGeoPointWithMetadataContract extends SmartContract {
  @state(Field) geoPointWithMetadata = State<Field>();
  @method async submitProof(proof: ExactGeolocationMetadataCircuitProof) {
    proof.verify();
    this.geoPointWithMetadata.set(proof.publicOutput);
  }
}
"""

_UNVERIFIED_PROOF = """
import { SmartContract, Field, State, state, method } from 'o1js';
class ExactGeolocationMetadataCircuitProof {}
export class ExactGeoPointWithMetadataContract extends SmartContract {
  @state(Field) geoPointWithMetadata = State<Field>();
  @method async submitProof(proof: ExactGeolocationMetadataCircuitProof) {
    this.geoPointWithMetadata.set(proof.publicOutput);
  }
}
"""

_PROOF_DATA_FIELD = """
import { SmartContract, Field, State, state, method } from 'o1js';
export class C extends SmartContract {
  @state(Field) slot = State<Field>();
  @method async submit(proofData: Field) {
    this.slot.set(proofData);
  }
}
"""


def test_verified_proof_suppresses_witness_findings():
    v = analyze_file("Exact.ts", _VERIFIED_PROOF)
    assert "O1JS_UNCONSTRAINED_WITNESS" not in _rules(v)
    assert "O1JS_WITNESS_NOT_BOUND_TO_STATE" not in _rules(v)
    assert "O1JS_UNVERIFIED_PROOF" not in _rules(v)


def test_unverified_proof_fires_high():
    v = analyze_file("Exact.ts", _UNVERIFIED_PROOF)
    fired = [x for x in v if x.rule_id == "O1JS_UNVERIFIED_PROOF"]
    assert fired and fired[0].severity == Severity.HIGH
    assert fired[0].evidence["witness"] == "proof"
    # Must not also spam unconstrained-witness on the same proof param.
    assert not [x for x in v if x.rule_id == "O1JS_UNCONSTRAINED_WITNESS"
                and x.evidence.get("witness") == "proof"]


def test_non_proof_param_named_proofData_unaffected():
    v = analyze_file("C.ts", _PROOF_DATA_FIELD)
    assert "O1JS_UNVERIFIED_PROOF" not in _rules(v)
    # Still a normal unconstrained witness flowing to state_set.
    amt = [x for x in v if x.evidence.get("witness") == "proofData"]
    assert amt and amt[0].rule_id == "O1JS_UNCONSTRAINED_WITNESS"


# ---------------------------------------------------------------------------
# OffchainState.settle(proof) — framework verifies; do not FP
# ---------------------------------------------------------------------------

_OFFCHAIN_STATE_SETTLE = """
import { SmartContract, method } from 'o1js';
class TokenInformationArrayProof {}
export class Doot extends SmartContract {
  @method async settle(proof: TokenInformationArrayProof) {
    await this.offchainState.settle(proof);
  }
}
"""

# A custom helper named settle must NOT get the OffchainState carve-out.
_CUSTOM_SETTLE_NO_VERIFY = """
import { SmartContract, Field, State, state, method } from 'o1js';
class SomeProof {}
export class C extends SmartContract {
  @state(Field) slot = State<Field>();
  @method async settle(proof: SomeProof) {
    this.myHelper.settle(proof);
    this.slot.set(proof.publicOutput);
  }
}
"""


def test_offchain_state_settle_suppresses_unverified_proof():
    v = analyze_file("Doot.ts", _OFFCHAIN_STATE_SETTLE)
    assert "O1JS_UNVERIFIED_PROOF" not in _rules(v), _rules(v)


def test_custom_settle_without_verify_still_fires():
    # Narrowness canary: only `this.offchainState.settle` is trusted.
    v = analyze_file("C.ts", _CUSTOM_SETTLE_NO_VERIFY)
    assert "O1JS_UNVERIFIED_PROOF" in _rules(v)


def test_rando_mina_shape_still_fires_after_offchain_carveout():
    # The zkLocus TP must remain visible after the OffchainState carve-out.
    src = """
import { SmartContract, Field, Poseidon, method } from 'o1js';
class RandomNumberObservationCircuitProof {}
export class RandoMinaContract extends SmartContract {
  @method async verifyRandomNumber(observationProof: RandomNumberObservationCircuitProof) {
    const claimedSender = observationProof.publicInput.sender;
    claimedSender.assertEquals(Poseidon.hash(this.sender.getUnconstrained().toFields()));
    const claimedNetworkState = observationProof.publicInput.networkState;
    this.network.stakingEpochData.ledger.hash.requireEquals(claimedNetworkState);
  }
}
"""
    v = analyze_file("RandoMinaContract.ts", src)
    fired = [x for x in v if x.rule_id == "O1JS_UNVERIFIED_PROOF"]
    assert fired and fired[0].evidence["witness"] == "observationProof"
