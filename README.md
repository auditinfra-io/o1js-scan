# o1js-scan

[![CI](https://github.com/auditinfra-io/o1js-scan/actions/workflows/ci.yml/badge.svg)](https://github.com/auditinfra-io/o1js-scan/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

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

# SARIF 2.1.0 for GitHub code scanning (writes o1js-scan.sarif by default)
o1js-scan src --sarif
o1js-scan src --sarif report.sarif   # or a named file, or - for stdout

# choose which severity fails CI (critical|high|medium|low|none; default high)
o1js-scan src --fail-on medium

o1js-scan --version
```

Exit code is `1` when a finding at or above the `--fail-on` level (default
`high`) is present and `0` otherwise — so you can drop it straight into CI.
With the default, a low/medium finding (including the informational recipient
rule below) does **not** fail the build; use `--fail-on none` to only report,
or `--fail-on medium` to gate more strictly. A missing scan path exits `2` with
an error on stderr, so a typo can't silently pass CI as a clean run. Every run
prints a one-line summary (counts by severity and the gate verdict) to stderr.

### Suppressing a reviewed finding

Silence a finding you've triaged without loosening the gate, with an inline
comment on — or on the line above — the flagged line:

```ts
this.send({ to, amount });  // o1js-scan-disable-line O1JS_UNCONSTRAINED_WITNESS

// o1js-scan-disable-next-line
this.send({ to, amount });
```

List one or more rule ids to suppress only those; a bare directive (no ids)
suppresses every rule on the target line.

As a library:

```python
from o1js_scan import analyze_file, analyze_project

for path, finding in analyze_project("src"):
    print(path, finding.rule_id, finding.severity.value, finding.title)
```

## GitHub Action

Add the scanner to CI in a few lines. Findings appear as annotations on the PR
diff and as alerts in the repository's **Security → Code scanning** tab.

```yaml
# .github/workflows/o1js-scan.yml
name: o1js-scan
on: [push, pull_request]

permissions:
  contents: read
  security-events: write   # required to upload SARIF to code scanning

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: auditinfra-io/o1js-scan@v0.5.0
        with:
          path: src              # optional, defaults to the repo root
          # version: 0.5.0       # optional, pin the scanner version
          # fail-on-findings: true   # optional, fail the job on any high/critical
```

Inputs: `path` (default `.`), `version` (PyPI version to install, default latest),
`upload-sarif` (default `true`), `fail-on-findings` (default `false` — by default
the scan reports as alerts without failing the build). SARIF upload needs
`security-events: write` and code scanning enabled (on by default for public
repos; private repos need GitHub Advanced Security). To gate the build instead of
(or in addition to) uploading alerts, set `fail-on-findings: true`.

## What it detects

| Rule | Severity | What it means |
|------|----------|---------------|
| `O1JS_MISSING_STATE_PRECONDITION` | high | `this.x.get()` read without a matching `requireEquals(...)` / `getAndRequireEquals()`. A bare `get()` adds **no** account precondition, so the proof doesn't bind `x` to its on-chain value — a prover can substitute any value. |
| `O1JS_UNCONSTRAINED_WITNESS` | high / medium | A `@method` argument (a prover-controlled private witness) flows into a `this.send` **amount** or a state `.set(...)` and is **never** asserted. Direct analog of an under-constrained Circom signal. High when it reaches a value transfer. |
| `O1JS_UNCONSTRAINED_PROVABLE_WITNESS` | high / medium / low | A `Provable.witness(...)` local flows into a send/state effect with **no** in-circuit assertion. The witness callback runs *outside* the circuit (it's only a prover hint), so the result is a fresh prover-controlled value — the other witness source besides `@method` args. It must be re-derived and asserted (`x.assertEquals(<recomputed>)`) or bound to state. High on a send amount, medium on a state write, low on a recipient. |
| `O1JS_UNCONSTRAINED_RECIPIENT` | low | A `@method` argument is used **only** as the `to:` recipient of `this.send(...)`. This is usually intended (a user names their own withdrawal destination) and is informational — it only matters if the destination is meant to be a fixed treasury or a state-recorded address. Does **not** trip the CI exit-code gate. |
| `O1JS_WITNESS_NOT_BOUND_TO_STATE` | medium | A witness is only *trivially* constrained (e.g. `> 0`, or compared against a constant) before an effect — never tied to on-chain state. Confirm the off-chain orchestration makes this safe, or the balance is drainable up to its standing value. |
| `O1JS_STALE_MERKLE_ROOT` | high | A method recomputes a Merkle root from a prover-supplied witness (`computeRootAndKey` / `calculateRoot`) but binds **none** of the recomputed roots to the current on-chain root. Without a `this.root.requireEquals(...)` / `assertEquals` against the live root, a prover can pass a witness for a fabricated or stale tree — forging membership or replaying old state. Binding may live in an undecorated same-class helper (`this.verifyX(witness)`); one level of helper propagation covers that. |
| `O1JS_UNVERIFIED_PROOF` | high | A `@method` parameter typed as `Proof<...>` / `SelfProof` / `DynamicProof` / `*Proof` is never `.verify()` / `.verifyIf()`'d. Passing a Proof does not verify it — without an explicit verify the prover can supply an arbitrary proof object, and any use of its `publicOutput` is unconstrained. |
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
  `amount.lessThanOrEqual(bal).assertTrue()`. Binding that lives in an
  undecorated same-class helper (`this.verifyX(arg)`) is also recognized
  (depth 1 only).
- **Verified proofs are skipped.** A `Proof` / `SelfProof` / `DynamicProof` /
  `*Proof`-typed argument on which `.verify()` / `.verifyIf()` is called is
  constrained by the verified circuit — witness findings on it (and its
  `publicOutput` / `publicInput`) are suppressed. The inverse case (proof-typed
  arg never verified) is reported as `O1JS_UNVERIFIED_PROOF`.
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

- **Cross-method binding is depth-1 only.** An undecorated same-class helper
  called as `this.verifyX(arg)` can state-bind a caller's argument (one level).
  Deeper chains (`@method` → helper A → helper B) and free/imported functions
  are **not** followed. Local-variable aliasing of the helper argument also
  stays a documented limitation.

- **Signature-gating is method-level and substring-based.**
  `_method_is_signature_gated` treats a whole `@method` as owner-gated if it
  contains a signature idiom, and it recognizes a verifier only when the
  receiver name literally contains `signature` — so `sig.verify(admin, msg)`
  is **not** recognized as gating, while an unrelated signature check elsewhere
  in a large method can over-suppress. It is all-or-nothing per method.

These are the reason findings are a starting point for human review, not
proofs. A dataflow-aware rewrite is deliberately out of scope for the
lexical analyzer.

## Compatibility

Works on **o1js 1.x and 2.x**. o1js-scan analyzes TypeScript source as text
and has **no runtime dependency on o1js** — nothing is version-pinned. It keys
on the modern `require*` precondition API (`getAndRequireEquals`,
`requireEquals`, `requireSignature`, `getAndRequireSignature`), the
`@method` / `@method.returns(...)` decorators, `@state`, `this.send({...})`,
and `Permissions.*`, all of which are unchanged across the 1.x → 2.x boundary.
The 2.x owner-auth idiom `this.sender.getAndRequireSignature()` is recognized
as signature-gating. (Legacy `assertEquals` preconditions are still accepted,
so older code isn't broken either.)

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
