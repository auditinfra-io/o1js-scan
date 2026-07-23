# o1js-scan

A fast, dependency-free static analyzer for **o1js / Mina zkApp** soundness bugs.

o1js zkApps compile TypeScript `@method` bodies into Kimchi circuits. Just like
Circom circuits, the security-critical bugs usually aren't in the proving system
(that's upstream o1Labs infrastructure) — they're in the **application's own
constraints**: witnesses the prover controls but the contract never binds, state
reads that never assert a precondition, and account permissions that let a
signature bypass the proof logic entirely.

`o1js-scan` finds those. It's the o1js analog of under-constrained-signal
scanning for Circom.

## Install

```bash
pip install o1js-scan
```

Or from source:

```bash
git clone https://github.com/auditinfra-io/o1js-scan
cd o1js-scan
pip install -e .
```

No third-party dependencies. Python 3.8+.

## Usage

```bash
# scan a directory (recursively; skips node_modules)
o1js-scan path/to/zkapp/src

# scan a single file
o1js-scan src/MyContract.ts

# machine-readable output for CI
o1js-scan src --json
```

Exit code is `1` when any high/critical finding is present and `0` otherwise —
so you can drop it straight into CI. A low/medium finding (including the
informational recipient rule below) does **not** fail the build. A missing
scan path exits `2` with an error on stderr, so a typo can't silently pass CI
as a clean run.

As a library:

```python
from o1js_scan import analyze_file, analyze_project

for path, finding in analyze_project("src"):
    print(path, finding.rule_id, finding.severity.value, finding.title)
```

## What it detects

| Rule | Severity | What it means |
|------|----------|---------------|
| `O1JS_MISSING_STATE_PRECONDITION` | high | `this.x.get()` read without a matching `requireEquals(...)` / `getAndRequireEquals()`. A bare `get()` adds **no** account precondition, so the proof doesn't bind `x` to its on-chain value — a prover can substitute any value. |
| `O1JS_UNCONSTRAINED_WITNESS` | high / medium | A `@method` argument (a prover-controlled private witness) flows into a `this.send` **amount** or a state `.set(...)` and is **never** asserted. Direct analog of an under-constrained Circom signal. High when it reaches a value transfer. |
| `O1JS_UNCONSTRAINED_RECIPIENT` | low | A `@method` argument is used **only** as the `to:` recipient of `this.send(...)`. This is usually intended (a user names their own withdrawal destination) and is informational — it only matters if the destination is meant to be a fixed treasury or a state-recorded address. Does **not** trip the CI exit-code gate. |
| `O1JS_WITNESS_NOT_BOUND_TO_STATE` | medium | A witness is only *trivially* constrained (e.g. `> 0`, or compared against a constant) before an effect — never tied to on-chain state. Confirm the off-chain orchestration makes this safe, or the balance is drainable up to its standing value. |
| `MissingRangeCheck` | high | A raw `Field` (not the range-checked `UInt64`/`UInt32`) is used as a transfer amount. A `Field` is an element mod p and is not range-bounded. |
| `O1JS_WEAK_PERMISSIONS` | high / medium | `editState` / `send` permission set to `proofOrSignature()` or `none()`, letting the zkApp account key bypass the circuit by signing. |

### False-positive guards

The analyzer is designed to stay quiet on correct code:

- **Signature-gated methods are skipped.** A `@method` that calls
  `this.requireSignature()` (or `getAndRequireSignature`, `AccountUpdate.createSigned`,
  `Signature.verify`) is owner/admin-gated — its arguments are chosen by the key
  holder, not an arbitrary prover — so its witnesses are not flagged. This is the
  o1js equivalent of `onlyOwner`.
- **State-bound witnesses are skipped.** An argument asserted equal to (or
  bounded by an ordering comparison against) a `getAndRequireEquals()`-derived
  value is sound and won't be reported. This covers both the direct form —
  `amount.assertLessThanOrEqual(bal)` — and the chained form
  `amount.lessThanOrEqual(bal).assertTrue()`.
- Comments and string literals are stripped before analysis, so an `assert`
  inside a string can't create a false result.

## Known limitations

The analyzer is a **lexical, name-matching** pass, not a dataflow engine.
Keep these blind spots in mind when triaging — they are known and intentional
for this dependency-free design, not bugs:

- **Aliasing defeats the taint.** Witness tracking matches argument *names*,
  so copying a witness through a local hides it:

  ```ts
  const q = qty; this.send({ to: dest, amount: q });   // qty is not flagged
  const slot = this.root; slot.get();                  // missing precondition missed
  ```

- **Signature-gating is method-level and substring-based.**
  `_method_is_signature_gated` treats a whole `@method` as owner-gated if it
  contains a signature idiom, and it recognizes a verifier only when the
  receiver name literally contains `signature` — so `sig.verify(admin, msg)`
  is **not** recognized as gating, while an unrelated signature check elsewhere
  in a large method can over-suppress. It is all-or-nothing per method.

These are the reason findings are a starting point for human review, not
proofs. A dataflow-aware rewrite is deliberately out of scope for the
lexical analyzer.

## How it works

It's a lexical analyzer, not a full TypeScript parser — o1js code is
decorator + brace-delimited-method-body shaped and regex-tractable, and the
output is meant to be triaged by a human. That keeps it dependency-free and
instant to run in CI. Findings are a starting point for review, not proofs.

## Roadmap / contributing

Contributions welcome — new rule families, more FP guards, and real-world
calibration archetypes are all valuable. Please add a test to `tests/` for any
new rule or guard. Run the suite with:

```bash
pip install -e ".[dev]"
pytest
```

## License

Apache-2.0. See [`LICENSE`](LICENSE).
