"""Focused tests for the rule-independent semantic-facts layer."""

from dataclasses import dataclass

from o1js_scan.semantic import SemanticFacts


@dataclass
class Method:
    name: str
    params: list
    body: str
    semantic_scope: int = 0


def test_alias_and_helper_effects_reach_fixed_point():
    methods = [
        Method("entry", ["x"], "const y = x; this.middle(y);"),
        Method("middle", ["a"], "const b = a; this.sink(b);"),
        Method("sink", ["amount"], "this.send({ to: receiver, amount });"),
    ]
    effect, constraint = SemanticFacts(methods, []).witness(methods[0], 0)
    assert effect is not None and effect.kind == "send_amount"
    assert constraint == "none"


def test_state_binding_propagates_separately_from_effect_chain():
    methods = [
        Method("entry", ["x"], "const y = x; this.check(y); this.sink(y);"),
        Method(
            "check", ["value"],
            "const available = this.reserve.getAndRequireEquals(); "
            "value.assertLessThanOrEqual(available);",
        ),
        Method("sink", ["amount"], "this.send({ to: receiver, amount });"),
    ]
    effect, constraint = SemanticFacts(methods, ["reserve"]).witness(methods[0], 0)
    assert effect is not None and effect.kind == "send_amount"
    assert constraint == "bound"


def test_same_named_methods_are_isolated_by_contract_scope():
    vulnerable = Method(
        "withdraw", ["amount"], "this.send({ to: receiver, amount });", 1
    )
    safe = Method(
        "withdraw", ["amount"],
        "const current = this.reserve.getAndRequireEquals(); "
        "amount.assertLessThanOrEqual(current);", 2,
    )
    facts = SemanticFacts([vulnerable, safe], ["reserve"])
    effect, constraint = facts.witness(vulnerable, 0)
    assert effect is not None and constraint == "none"
    assert facts.witness(safe, 0)[1] == "bound"


def test_compound_call_argument_does_not_bind_each_operand():
    entry = Method(
        "entry", ["a", "b"],
        "this.check(a.add(b)); this.send({ to: receiver, amount: a });",
    )
    check = Method(
        "check", ["value"],
        "const current = this.reserve.getAndRequireEquals(); "
        "value.assertEquals(current);",
    )
    facts = SemanticFacts([entry, check], ["reserve"])
    effect, constraint = facts.witness(entry, 0)
    assert effect is not None and constraint == "none"


def test_typed_alias_and_state_local_propagate_through_helper():
    entry = Method(
        "entry", ["requested"],
        "const renamed: UInt64 = requested; this.checkAndSend(renamed);",
    )
    helper = Method(
        "checkAndSend", ["amount"],
        "const available: UInt64 = this.reserve.getAndRequireEquals(); "
        "amount.assertLessThanOrEqual(available); this.send({ to: receiver, amount });",
    )
    effect, constraint = SemanticFacts([entry, helper], ["reserve"]).witness(entry, 0)
    assert effect is not None and effect.kind == "send_amount"
    assert constraint == "bound"


def test_account_update_local_send_propagates_through_helper():
    entry = Method("entry", ["requested"], "this.transfer(requested);")
    helper = Method(
        "transfer", ["amount"],
        "const au: AccountUpdate = AccountUpdate.create(sender); "
        "au.send({ to: receiver, amount });",
    )
    effect, constraint = SemanticFacts([entry, helper], []).witness(entry, 0)
    assert effect is not None and effect.kind == "send_amount"
    assert constraint == "none"


def test_chained_account_update_send_propagates_through_helper():
    entry = Method("entry", ["recipient"], "this.transfer(recipient);")
    helper = Method(
        "transfer", ["to"],
        "AccountUpdate.create(sender).send({ to, amount: UInt64.one });",
    )
    effect, _ = SemanticFacts([entry, helper], []).witness(entry, 0)
    assert effect is not None and effect.kind == "send_recipient"


def test_account_update_balance_debit_is_a_transfer_effect():
    entry = Method("entry", ["requested"], "this.transfer(requested);")
    helper = Method(
        "transfer", ["amount"],
        "const payer = AccountUpdate.create(sender); payer.balance.subInPlace(amount);",
    )
    effect, _ = SemanticFacts([entry, helper], []).witness(entry, 0)
    assert effect is not None and effect.kind == "send_amount"


def test_chained_account_update_balance_debit_is_a_transfer_effect():
    method = Method(
        "transfer", ["amount"],
        "AccountUpdate.create(sender).balance.subInPlace(amount);",
    )
    effect, _ = SemanticFacts([method], []).witness(method, 0)
    assert effect is not None and effect.kind == "send_amount"


def test_explanation_records_alias_calls_mappings_and_real_sink_lines():
    methods = [
        Method("withdraw", ["amount"], "\nconst requested = amount;\nthis.middle(requested);"),
        Method("middle", ["value"], "\nthis.transfer(value);"),
        Method("transfer", ["sent"], "\nthis.send({ to: receiver, amount: sent });"),
    ]
    # The lightweight test Method has no start_line, so all values are still
    # actual body-relative lines rather than invented callee call-site lines.
    explanation = SemanticFacts(methods, []).explain_witness(methods[0], 0)
    assert explanation is not None
    assert [step.kind for step in explanation.flow] == [
        "source", "alias", "call", "parameter", "call", "parameter", "sink",
    ]
    assert explanation.binding == "none"
    assert explanation.flow[-1].method == "transfer"
    assert explanation.flow[-1].line == 2


def test_ambiguous_multiple_effect_paths_have_no_explanation():
    entry = Method(
        "entry", ["amount"],
        "this.first(amount); this.second(amount);",
    )
    first = Method("first", ["x"], "this.send({ to: a, amount: x });")
    second = Method("second", ["x"], "this.send({ to: b, amount: x });")
    facts = SemanticFacts([entry, first, second], [])
    assert facts.witness(entry, 0)[0] is not None
    assert facts.explain_witness(entry, 0) is None


def test_duplicate_helper_name_is_not_treated_as_exact_call_edge():
    entry = Method("entry", ["amount"], "this.transfer(amount);")
    helpers = [
        Method("transfer", ["x"], "this.send({ to: a, amount: x });"),
        Method("transfer", ["x"], "this.send({ to: b, amount: x });"),
    ]
    facts = SemanticFacts([entry] + helpers, [])
    assert facts.witness(entry, 0)[0] is None
    assert facts.explain_witness(entry, 0) is None
