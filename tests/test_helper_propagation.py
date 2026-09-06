"""Binding facts must survive a chain of same-class helpers, and terminate.

WHY THIS EXISTS
---------------
Binding propagation used to stop after one level. It now runs to a fixed point,
so `checkAll(x) -> checkMid(x) -> checkOne(x) -> x.assertEquals(state)` marks
all three helpers as binding rather than only the innermost.

Honest scope: no end-to-end finding is known to change because of this. The
`SemanticFacts` layer added in 0.14.0 already suppressed the multi-level witness
case by another route, so every test below passes with the fixed point disabled
too. What these tests pin is the *specification* — chains are followed, and the
negative cases must never launder a witness — so a future change that leans on
`helper_binds` alone cannot silently regress it.

Following chains introduces the opposite risk: recursion, mutual recursion, and
argument mappings that cannot be established. Those are pinned below as well.

Termination is structural: binding sets only grow and are bounded by the
parameter count, so a cycle converges rather than looping. The recursion tests
would hang, not fail, if that stopped being true.
"""

from __future__ import annotations

from o1js_scan import analyze_file

WITNESS = "O1JS_UNCONSTRAINED_WITNESS"
HEAD = "import { SmartContract, method, state, State, Field, UInt64, PublicKey } from 'o1js';\n"


def _rules(src: str) -> set:
    return {v.rule_id for v in analyze_file("src/contracts/Vault.ts", HEAD + src)}


def _contract(body: str) -> str:
    return (
        "export class Vault extends SmartContract {\n"
        "  @state(Field) root = State<Field>();\n" + body + "\n}\n"
    )


# ───────────────────────────────────────────────────────────────────
# Depth: a real binding must be found however deeply it is factored
# ───────────────────────────────────────────────────────────────────

def test_depth_1_binding_still_suppresses():
    assert WITNESS not in _rules(_contract("""
  checkOne(x: Field) { x.assertEquals(this.root.getAndRequireEquals()); }
  @method async use(x: Field) { this.checkOne(x); this.root.set(x); }"""))


def test_depth_2_binding_suppresses():
    assert WITNESS not in _rules(_contract("""
  checkOne(x: Field) { x.assertEquals(this.root.getAndRequireEquals()); }
  checkAll(x: Field) { this.checkOne(x); }
  @method async use(x: Field) { this.checkAll(x); this.root.set(x); }"""))


def test_depth_3_binding_suppresses():
    assert WITNESS not in _rules(_contract("""
  checkOne(x: Field) { x.assertEquals(this.root.getAndRequireEquals()); }
  checkMid(x: Field) { this.checkOne(x); }
  checkAll(x: Field) { this.checkMid(x); }
  @method async use(x: Field) { this.checkAll(x); this.root.set(x); }"""))


def test_argument_reordering_is_followed():
    """The mapping is positional, so a swap must be tracked, not assumed."""
    assert WITNESS not in _rules(_contract("""
  checkOne(ignored: Field, x: Field) { x.assertEquals(this.root.getAndRequireEquals()); }
  checkAll(x: Field, other: Field) { this.checkOne(other, x); }
  @method async use(x: Field, y: Field) { this.checkAll(x, y); this.root.set(x); }"""))


# ───────────────────────────────────────────────────────────────────
# The other direction: a chain that binds nothing must not launder
# ───────────────────────────────────────────────────────────────────

def test_helper_chain_that_never_binds_does_not_suppress():
    """Helpers named like checks, doing none. The finding must survive."""
    assert WITNESS in _rules(_contract("""
  checkOne(x: Field) { x.add(1); }
  checkAll(x: Field) { this.checkOne(x); }
  @method async use(x: Field) { this.checkAll(x); this.root.set(x); }"""))


def test_helper_returning_an_unasserted_bool_does_not_suppress():
    assert WITNESS in _rules(_contract("""
  isValid(x: Field) { return x.equals(this.root.getAndRequireEquals()); }
  @method async use(x: Field) { this.isValid(x); this.root.set(x); }"""))


def test_derived_argument_does_not_map_back():
    """`checkAll(x.add(1))` says nothing about `x`; mapping must bail out."""
    assert WITNESS in _rules(_contract("""
  checkOne(x: Field) { x.assertEquals(this.root.getAndRequireEquals()); }
  checkAll(x: Field) { this.checkOne(x); }
  @method async use(x: Field) { this.checkAll(x.add(1)); this.root.set(x); }"""))


def test_unrelated_helper_call_does_not_suppress():
    assert WITNESS in _rules(_contract("""
  checkOther(y: Field) { y.assertEquals(this.root.getAndRequireEquals()); }
  @method async use(x: Field, y: Field) { this.checkOther(y); this.root.set(x); }"""))


# ───────────────────────────────────────────────────────────────────
# Cycles must converge, not hang
# ───────────────────────────────────────────────────────────────────

def test_direct_recursion_terminates():
    rules = _rules(_contract("""
  loop(x: Field) { this.loop(x); }
  @method async use(x: Field) { this.loop(x); this.root.set(x); }"""))
    assert WITNESS in rules, "a helper that only recurses binds nothing"


def test_mutual_recursion_terminates():
    rules = _rules(_contract("""
  ping(x: Field) { this.pong(x); }
  pong(x: Field) { this.ping(x); }
  @method async use(x: Field) { this.ping(x); this.root.set(x); }"""))
    assert WITNESS in rules, "a mutually recursive pair binds nothing"


def test_recursion_with_a_real_binding_still_converges_and_suppresses():
    assert WITNESS not in _rules(_contract("""
  ping(x: Field) { x.assertEquals(this.root.getAndRequireEquals()); this.pong(x); }
  pong(x: Field) { this.ping(x); }
  @method async use(x: Field) { this.pong(x); this.root.set(x); }"""))


# ───────────────────────────────────────────────────────────────────
# Scope
# ───────────────────────────────────────────────────────────────────

def test_cross_class_calls_remain_out_of_scope():
    """Only `this.<helper>()` is followed; another contract's method is not."""
    src = HEAD + """
export class Other extends SmartContract {
  check(x: Field) { x.assertEquals(Field(1)); }
}
export class Vault extends SmartContract {
  @state(Field) root = State<Field>();
  @method async use(x: Field) { new Other(this.address).check(x); this.root.set(x); }
}
"""
    assert WITNESS in {v.rule_id for v in analyze_file("src/contracts/Vault.ts", src)}
