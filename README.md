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

Exit code is `1` when any high/critical finding is present, `0` otherwise — so
you can drop it straight into CI.

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
| `O1JS_UNCONSTRAINED_WITNESS` | high / medium | A `@method` argument (a prover-controlled private witness) flows into `this.send` or a state `.set(...)` and is **never** asserted. Direct analog of an under-constrained Circom signal. High when it reaches a value transfer. |
| `O1JS_WITNESS_NOT_BOUND_TO_STATE` | medium | A witness is only *trivially* constrained (e.g. `> 0`) before an effect — never tied to on-chain state. Confirm the off-chain orchestration makes this safe, or the balance is drainable up to its standing value. |
| `MissingRangeCheck` | high | A raw `Field` (not the range-checked `UInt64`/`UInt32`) is used as a transfer amount. A `Field` is an element mod p and is not range-bounded. |
| `O1JS_WEAK_PERMISSIONS` | high / medium | `editState` / `send` permission set to `proofOrSignature()` or `none()`, letting the zkApp account key bypass the circuit by signing. |

### False-positive guards

The analyzer is designed to stay quiet on correct code:

- **Signature-gated methods are skipped.** A `@method` that calls
  `this.requireSignature()` (or `getAndRequireSignature`, `AccountUpdate.createSigned`,
  `Signature.verify`) is owner/admin-gated — its arguments are chosen by the key
  holder, not an arbitrary prover — so its witnesses are not flagged. This is the
  o1js equivalent of `onlyOwner`.
- **State-bound witnesses are skipped.** An argument asserted equal to a
  `getAndRequireEquals()`-derived value is sound and won't be reported.
- Comments and string literals are stripped before analysis, so an `assert`
  inside a string can't create a false result.

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
