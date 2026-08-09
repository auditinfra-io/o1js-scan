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
