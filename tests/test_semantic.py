"""Focused tests for the rule-independent semantic-facts layer."""

from dataclasses import dataclass

from o1js_scan.semantic import SemanticFacts


@dataclass
class Method:
    name: str
    params: list
    body: str


def test_alias_and_helper_effects_reach_fixed_point():
    methods = [
        Method("entry", ["x"], "const y = x; this.middle(y);"),
        Method("middle", ["a"], "const b = a; this.sink(b);"),
        Method("sink", ["amount"], "this.send({ to: receiver, amount });"),
    ]
    effect, constraint = SemanticFacts(methods, []).witness("entry", 0)
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
    effect, constraint = SemanticFacts(methods, ["reserve"]).witness("entry", 0)
    assert effect is not None and effect.kind == "send_amount"
    assert constraint == "bound"
