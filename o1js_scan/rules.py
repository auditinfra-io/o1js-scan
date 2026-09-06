"""The single source of truth for rule metadata.

WHY THIS EXISTS
---------------
Rule metadata used to live in three places that nothing kept in step: the
detector that emits a finding, the README table a user triages from, and the
SARIF writer that labels it for code scanning. Three separate documentation
tests existed only to catch the resulting drift by hand, and all three fired
during 0.17.0 development.

This module holds the metadata; ``scripts/render_rule_docs.py`` renders the
README tables and ``docs/rules.md`` from it, and ``sarif.py`` reads it for
per-rule SARIF metadata. Detection logic deliberately stays in ``lexer.py`` and
``noir.py`` for now — moving metadata and moving detectors in one step would
make the diff unreviewable.

Adding a rule means adding a :class:`RuleSpec` here and running
``python3 scripts/render_rule_docs.py``; the tests fail otherwise.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Tuple

__all__ = ["RuleSpec", "REGISTRY", "BACKENDS", "SEVERITIES", "spec_for", "specs_for_backend"]

BACKENDS = ("o1js", "noir")

# Ordered most severe first; a rule's default severity is the first it can emit.
SEVERITIES = ("critical", "high", "medium", "low", "info")


@dataclass(frozen=True)
class RuleSpec:
    """Immutable metadata for one rule.

    ``severities`` is the full spread a rule can emit, not just one level: most
    rules here vary severity by how load-bearing the finding is, and the README
    table documents that spread. The first entry is the default.
    """

    rule_id: str
    backend: str
    title: str
    severities: Tuple[str, ...]
    description: str
    tags: Tuple[str, ...] = ()
    origin: Optional[str] = None
    metadata_only: bool = False

    @property
    def default_severity(self) -> str:
        return self.severities[0]

    @property
    def severity_label(self) -> str:
        """How the spread reads in the rendered table, e.g. ``high / medium``."""
        return " / ".join(self.severities)

    @property
    def help_anchor(self) -> str:
        """Anchor into ``docs/rules.md``; GitHub lowercases heading text."""
        return self.rule_id.lower()


_BACKEND_TAGS = {
    "o1js": ("security", "zk", "o1js", "mina"),
    "noir": ("security", "zk", "noir", "aztec"),
}


def _rule(rule_id, backend, title, severities, description, origin=None):
    return RuleSpec(
        rule_id=rule_id,
        backend=backend,
        title=title,
        severities=severities,
        description=description,
        tags=_BACKEND_TAGS[backend],
        origin=origin,
    )


_SPECS = (
    # ---- o1js ----
    _rule(
        "O1JS_MISSING_STATE_PRECONDITION",
        "o1js",
        "Missing state precondition",
        ('high',),
        "`this.x.get()` read without a matching `requireEquals(...)` / `getAndRequireEquals()`. A bare `get()` adds **no** account precondition, so the proof doesn't bind `x` to its on-chain value — a prover can substitute any value.",
    ),
    _rule(
        "O1JS_UNCONSTRAINED_WITNESS",
        "o1js",
        "Unconstrained witness",
        ('high', 'medium'),
        "A `@method` argument (a prover-controlled private witness) flows into a send **amount** (`this.send(...)` or a same-method `AccountUpdate.create*(...).send(...)`) or a state `.set(...)` and is **never** asserted. Direct analog of an under-constrained Circom signal. High when it reaches a value transfer.",
    ),
    _rule(
        "O1JS_UNCONSTRAINED_PROVABLE_WITNESS",
        "o1js",
        "Unconstrained provable witness",
        ('high', 'medium', 'low'),
        "A `Provable.witness(...)` local flows into a send/state effect with **no** in-circuit assertion. The witness callback runs *outside* the circuit (it's only a prover hint), so the result is a fresh prover-controlled value — the other witness source besides `@method` args. It must be re-derived and asserted (`x.assertEquals(<recomputed>)`) or bound to state. High on a send amount (`this.send(...)` or same-method `AccountUpdate.create*`).",
    ),
    _rule(
        "O1JS_UNCONSTRAINED_RECIPIENT",
        "o1js",
        "Unconstrained recipient",
        ('low',),
        "A `@method` argument is used **only** as the `to:` recipient of a send. This is usually intended (a user names their own withdrawal destination) and is informational — it only matters if the destination is meant to be a fixed treasury or a state-recorded address. Does **not** trip the CI exit-code gate.",
    ),
    _rule(
        "O1JS_WITNESS_NOT_BOUND_TO_STATE",
        "o1js",
        "Witness not bound to state",
        ('medium',),
        "A witness is only *trivially* constrained (e.g. `> 0`, or compared against a constant) before an effect — never tied to on-chain state. Confirm the off-chain orchestration makes this safe, or the balance is drainable up to its standing value.",
    ),
    _rule(
        "O1JS_STALE_MERKLE_ROOT",
        "o1js",
        "Stale merkle root",
        ('high',),
        "A method recomputes a Merkle root from a prover-supplied witness (`computeRootAndKey` / `calculateRoot`) but binds **none** of the recomputed roots to the current on-chain root. Without a `this.root.requireEquals(...)` / `assertEquals` against the live root, a prover can pass a witness for a fabricated or stale tree — forging membership or replaying old state. Binding may live in an undecorated same-class helper (`this.verifyX(witness)`); one level of helper propagation covers that.",
    ),
    _rule(
        "O1JS_UNVERIFIED_PROOF",
        "o1js",
        "Unverified proof",
        ('high',),
        "A `@method` parameter typed as `Proof<...>` / `SelfProof` / `DynamicProof` / `*Proof` is never `.verify()`'d before its public fields are used. Passing a Proof does not verify it — without an explicit verify the prover can supply an arbitrary proof object, and any use of its `publicOutput` is unconstrained. Also fires when `.verifyIf(flag)` is gated by an unconstrained `@method` argument and the proof's public fields are read, because the prover can make the condition false.",
    ),
    _rule(
        "O1JS_UNASSERTED_BOOL",
        "o1js",
        "Unasserted bool",
        ('high', 'medium'),
        "An o1js predicate (`equals` / `lessThanOrEqual` / …) returns a `Bool` and adds **no** constraint unless the result is asserted or used. HIGH when the call is a bare discarded statement; MEDIUM when assigned to a local that is never referenced again.",
    ),
    _rule(
        "O1JS_UNCONSTRAINED_SENDER",
        "o1js",
        "Unconstrained sender",
        ('high', 'medium'),
        "`this.sender.getUnconstrained()` returns the tx sender without proving it. HIGH when that value (or a local from it) flows into an assert / state `.set` / `send` (vacuous check); MEDIUM otherwise. Prefer `this.sender.getAndRequireSignature()`, or the expanded idiom `AccountUpdate.createSigned(sender)`. **Stays quiet when** (1) the same `@method` also calls `this.sender.getAndRequireSignature()` anywhere (signature requirement is method-scoped), or (2) the witnessed sender value is the argument to `AccountUpdate.createSigned(...)` / an `AccountUpdate.create(...).requireSignature()` on that same key (argument identity required — a `createSigned` on a different key does not suppress).",
    ),
    _rule(
        "MissingRangeCheck",
        "o1js",
        "Missing Range Check",
        ('high',),
        "A raw `Field` (not the range-checked `UInt64`/`UInt32`) is used as a transfer amount. A `Field` is an element mod p and is not range-bounded.",
    ),
    _rule(
        "O1JS_WEAK_PERMISSIONS",
        "o1js",
        "Weak permissions",
        ('high', 'medium'),
        "`editState` / `send` set to `proofOrSignature()` or `none()`, letting the zkApp account key bypass the circuit by signing. Also flags `setVerificationKey` / `setPermissions` left at `signature` / `proofOrSignature` / `none` (Mina's documented upgrade training wheels); HIGH when combined with a weak `editState`/`send` in the same `permissions.set`.",
    ),
    _rule(
        "O1JS_LOGIC_OUTSIDE_PROOF",
        "o1js",
        "Logic outside proof",
        ('high',),
        "Security logic (assert / approve / send / state `.set`) inside `Provable.asProver(...)` or a `Provable.witness*` callback. Those callbacks run *outside* the circuit — a malicious prover can delete them and still produce a verifying proof.",
    ),
    _rule(
        "O1JS_APPROVE_WITHOUT_BINDING",
        "o1js",
        "Approve without binding",
        ('medium',),
        "A `@method` calls `approve` / `approveAccountUpdate` / `approveBase` without reading `balanceChange` / `publicKey` and without `assertCanMint` / `assertCanBurn` / a `forEachUpdate` conservation check — the Mina FlawedTokenContract archetype.",
    ),
    _rule(
        "O1JS_VACUOUS_ASSERT",
        "o1js",
        "Vacuous assert",
        ('high', 'medium'),
        "An assert that is satisfied by construction: `x.assertEquals(x)`, `x.equals(x).assertTrue()`, or `Bool(true).assertTrue()`. HIGH for self-comparisons (almost always a typo); MEDIUM for constant Bool asserts.",
    ),
    _rule(
        "O1JS_CONDITIONAL_ASSERT",
        "o1js",
        "Conditional assert",
        ('medium',),
        "An assert inside `if <flag> { ... }` where `<flag>` is a prover-controlled `@method` `Bool` (or a local from `.toBoolean()`). A JS conditional does not constrain the circuit the way `Provable.if` does. Inline comparisons stay unreported for precision.",
    ),
    _rule(
        "O1JS_GUARDED_INVERSE",
        "o1js",
        "Guarded inverse",
        ('medium',),
        "A `.div()` / `.inv()` / `.sqrt()` inside a `Provable.if` branch, guarded by a condition on the very value it fails on. Both branches are evaluated in-circuit and these calls assert unconditionally that the inverse or root exists, so the guard does not skip the assertion — the circuit is unsatisfiable for exactly the input the guard was written to handle, and the method can never be proven for it. Reported by Veridise as `V-O1J-VUL-060`. Compute a safe divisor first (`Provable.if(isZero, Field(1), d)`) and select the result afterwards. **Stays quiet when** the guard says nothing about the divisor, so an unrelated `Provable.if` around a safe division is not flagged.",
        origin="V-O1J-VUL-060",
    ),
    _rule(
        "O1JS_PRECONDITION_OVERWRITTEN",
        "o1js",
        "Precondition overwritten",
        ('medium',),
        "Two or more `requireEquals` / `requireBetween` / `requireNothing` calls on the **same** property in one method, with differing arguments. Preconditions are *set* on the AccountUpdate rather than accumulated, so each call overwrites the previous one and only the last is enforced — unlike in-circuit assertions, which compose. `a.requireEquals(b)` then `a.requireEquals(c)` implies `a === c`, not `a === b`. Reported by Veridise as `V-O1J-VUL-012`. **Stays quiet when** the arguments are identical (idempotent, nothing lost), on `getAndRequireEquals()` (a different method, so repeated state reads are fine), and when the calls sit in mutually exclusive JS branches, which are resolved at circuit-build time. That last exemption can hide a real overwrite that straddles an unrelated `if`/`else`.",
        origin="V-O1J-VUL-012",
    ),
    _rule(
        "O1JS_STATE_READ_AFTER_WRITE",
        "o1js",
        "State read after write",
        ('medium',),
        "A `@state` field is read (`get()` / `getAndRequireEquals()`) after a `set(...)` on the same field completes, in the same method. `set()` records the change on the AccountUpdate but does not write through to `get()`, so the read still observes the value from before the write and any arithmetic built on it is silently off by that write. Reported by Veridise as `V-O1J-VUL-030`. Keep the new value in a local instead of reading the state back. **Stays quiet when** the read is nested inside the write's own arguments (the read-modify-write idiom `this.x.set(this.x.getAndRequireEquals().add(1))`, which is correct), and when the write and read sit in mutually exclusive JS branches. Scoped to a single method — the cross-method caching case Veridise also describes needs call-graph knowledge this rule does not have.",
        origin="V-O1J-VUL-030",
    ),
    # ---- noir ----
    _rule(
        "NOIR_UNCONSTRAINED_WITNESS",
        "noir",
        "Unconstrained witness",
        ('high',),
        "A value bound from an `unsafe { ... }` block — the result of an `unconstrained fn` (oracle / Brillig hint) — that is never re-constrained by an `assert` / `assert_eq` (or a confirming helper / merkle check). The hint runs **outside** the circuit. Analog of `O1JS_UNCONSTRAINED_PROVABLE_WITNESS`.",
    ),
    _rule(
        "NOIR_UNCONSTRAINED_INPUT",
        "noir",
        "Unconstrained input",
        ('medium',),
        "A private (witness) input of `fn main` that flows into **no** `assert` / `assert_eq` and is **not** part of the public output. Analog of `O1JS_UNCONSTRAINED_WITNESS`.",
    ),
    _rule(
        "NOIR_UNCONSTRAINED_PUBLIC_INPUT",
        "noir",
        "Unconstrained public input",
        ('medium',),
        "A **public** input of `fn main` that reaches no constraint and no output — the circuit never reads it. The *dual* of the private-witness rule: the verifier supplies the value and believes the statement is about it, while the circuit ignores it (e.g. a `merkle_root: pub Field` that is never checked, so membership was never actually proven). MEDIUM because a deliberately unused public input is also a legitimate idiom for binding a proof to a context (nonce / chain id / recipient), which is indistinguishable lexically — so it does not gate CI at the default `--fail-on high`.",
    ),
    _rule(
        "NOIR_UNCHECKED_CAST",
        "noir",
        "Unchecked cast",
        ('medium',),
        "A prover-controlled value cast to a narrow unsigned type (`as u8`/`u16`/`u32`) with **no** range assertion. Analog of o1js `MissingRangeCheck`.",
    ),
    _rule(
        "NOIR_UNCONSTRAINED_ARRAY_INDEX",
        "noir",
        "Unconstrained array index",
        ('medium',),
        "A prover-controlled value used as an array index (`arr[i]`) with **no** check of any kind on it. Noir's implicit bounds check establishes only that the index is *in range* — not that it is the *correct* index — so the prover stays free to select any element and still produce a verifying proof. This is the selector-freedom bug behind Merkle path positions, note selection and allow-list membership. Suppressed when the index is range-bounded, pinned by an equality, bounded before a cast (`index.assert_max_bit_size::<8>(); let i = index as u32;`), or when the value read back is itself pinned by an `assert_eq`.",
    ),
    _rule(
        "NOIR_UNASSERTED_BOOL",
        "noir",
        "Unasserted bool",
        ('high', 'medium'),
        "A comparison whose `bool` result is **discarded**. Analog of o1js `O1JS_UNASSERTED_BOOL`.",
    ),
    _rule(
        "NOIR_CONDITIONAL_ASSERT",
        "noir",
        "Conditional assert",
        ('medium',),
        "An `assert` inside `if <flag> { ... }` where `<flag>` is a prover-controlled bare `bool` or a local derived from prover-controlled values. A constraint inside a conditional only applies when the condition is true, so a prover-chosen branch can skip the check. Inline comparisons (`if x != 0`) are left alone for precision; assigning the guard to a local (`let gate = x != 0; if gate`) is reported unless `gate` is itself asserted.",
    ),
    _rule(
        "NOIR_CONDITIONAL_CONSTRAIN",
        "noir",
        "Conditional constrain",
        ('medium',),
        "A `constrain_*` / `confirm_*` / `verify_*` call only under a prover-controlled `if`, while an `unsafe` hint still reaches the output.",
    ),
    _rule(
        "NOIR_UNUSED_CHECK_RESULT",
        "noir",
        "Unused check result",
        ('high', 'medium'),
        "A `check_*` / `confirm_*` / `verify_*` / `constrain_*` result is discarded (bare call) or assigned and never asserted — the check does not bind the circuit.",
    ),
    _rule(
        "NOIR_VACUOUS_CONSTRAINT",
        "noir",
        "Vacuous constraint",
        ('high', 'medium'),
        "A constraint that is satisfied by construction: a self-comparison (`assert(x == x)`, `assert_eq(x, x)`, `x >= x`) or a constant condition (`assert(true)`). It adds no restriction, but the line *reads* as a check — which makes it more dangerous than a missing constraint, because review stops there. HIGH for a self-comparison (almost always a typo for a real check: `assert(computed == expected)` mistyped as `assert(expected == expected)`); MEDIUM for a constant, which is more often a placeholder. `x != x` is **not** flagged — that is unsatisfiable, a liveness bug rather than a silent soundness hole.",
    ),
    _rule(
        "NOIR_UNSAFE_MISSING_SAFETY",
        "noir",
        "Unsafe missing safety",
        ('low',),
        "An `unsafe { ... }` block with no adjacent `// Safety:` comment. Informational; does not fail CI at default `--fail-on high`.",
    ),
)

REGISTRY: Dict[str, RuleSpec] = {spec.rule_id: spec for spec in _SPECS}


def spec_for(rule_id: str) -> Optional[RuleSpec]:
    return REGISTRY.get(rule_id)


def specs_for_backend(backend: str) -> Tuple[RuleSpec, ...]:
    """Registration order, which is the order the rendered tables use."""
    return tuple(s for s in _SPECS if s.backend == backend)
