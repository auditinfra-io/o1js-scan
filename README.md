# o1js-scan

[![CI](https://github.com/auditinfra-io/o1js-scan/actions/workflows/ci.yml/badge.svg)](https://github.com/auditinfra-io/o1js-scan/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![PyPI](https://img.shields.io/pypi/v/o1js-scan.svg)](https://pypi.org/project/o1js-scan/)

A fast, dependency-free static analyzer for **zk circuit soundness bugs** in:

- **o1js / Mina zkApps** (TypeScript `.ts` / `.js`) — Kimchi circuits from `@method` bodies
- **Noir** (`.nr`) — Aztec's Rust-like ZK DSL (including aztec-nr-shaped patterns)

The security-critical bugs usually aren't in the proving system — they're in the
**application's own constraints**: witnesses the prover controls but the circuit
never binds. `o1js-scan` is the under-constrained-signal scanner for Circom's
cousins in the Mina and Noir ecosystems.

```bash
pip install o1js-scan
# or: pipx install o1js-scan
# or: npm install -D o1js-scan

o1js-scan path/to/zkapp          # o1js + Noir (auto)
noir-scan path/to/circuits       # same binary — Noir-friendly alias
noir-scan . --lang noir --fail-on high --sarif noir.sarif
```

### Example

Given a vault whose `withdraw` amount is a prover-controlled witness that is
never bound to on-chain state:

```console
$ o1js-scan examples/vulnerable_vault.ts --include-examples
LOW      O1JS_UNCONSTRAINED_RECIPIENT       vulnerable_vault.ts:23  fn=withdraw  Recipient `to` is prover-chosen in `withdraw`
HIGH     O1JS_UNCONSTRAINED_WITNESS         vulnerable_vault.ts:23  fn=withdraw  Unconstrained witness `amount` flows to send_amount in `withdraw`
o1js-scan: 2 finding(s) [1 high, 1 low] in 1 file(s) — fails (--fail-on high)
$ echo $?
1
```

`--include-examples` is needed here only because the demo file lives under
`examples/`, which the path classifier downgrades by default so that a repo's
own sample code cannot fail its build. The same contract in your `src/` reports
`HIGH` with no flag.

The `HIGH` finding is the drainable bug. The fixed contract
(`examples/safe_vault.ts`) drops it and exits `0`, keeping only the informational
`LOW` on the prover-chosen recipient:

```console
$ o1js-scan examples/safe_vault.ts --include-examples
LOW      O1JS_UNCONSTRAINED_RECIPIENT       safe_vault.ts:23  fn=withdraw  Recipient `to` is prover-chosen in `withdraw`
o1js-scan: 1 finding(s) [1 low] in 1 file(s) — passes (--fail-on high)
$ echo $?
0
```

See [`examples/`](examples/) for the o1js and Noir vulnerable/fixed pairs.

## Contents

- [Install](#install)
- [Usage](#usage) · [Suppressing a finding](#suppressing-a-reviewed-finding)
- [GitHub Action](#github-action)
- [What it detects — o1js](#what-it-detects-o1js) · [Noir](#what-it-detects-noir)
- [Known limitations](#known-limitations) · [Where this tool stops](#where-this-tool-stops)
- [Compatibility](#compatibility) · [How it works](#how-it-works)
- [Contributing](#roadmap--contributing)

## Install

```bash
pip install o1js-scan
```

For an isolated global CLI install, use `pipx`:

```bash
pipx install o1js-scan
```

For Node/npm-based Noir, Aztec, or o1js app repositories, install the npm wrapper:

```bash
npm install -D o1js-scan
npx noir-scan . --lang noir --fail-on high
```

The npm package is a thin wrapper around the same Python analyzer and requires
Python 3.8+ on `PATH` (`python3` or `python`). Set `O1JS_SCAN_PYTHON` to choose a
specific interpreter.

Or from source:

```bash
git clone https://github.com/auditinfra-io/o1js-scan
cd o1js-scan
pip install -e .
```

No third-party Python dependencies. Python 3.8+. The `noir-scan` console script is
installed alongside `o1js-scan` (same entry point), including through the npm
wrapper.

## Usage

```bash
# scan a directory (recursively; skips node_modules, target/, .git, …)
o1js-scan path/to/project

# Noir-only / o1js-only
noir-scan circuits --lang noir
o1js-scan src --lang o1js

# scan a single file
o1js-scan src/MyContract.ts
noir-scan src/main.nr

# machine-readable output for CI
o1js-scan src --json

# SARIF 2.1.0 for GitHub code scanning (writes o1js-scan.sarif by default)
o1js-scan src --sarif
noir-scan . --lang noir --sarif noir.sarif

# choose which severity fails CI (critical|high|medium|low|none; default high)
o1js-scan src --fail-on medium

# test code is excluded by default (both backends); opt back in
o1js-scan src --include-tests

# example code is downgraded to LOW by default; keep original severity
o1js-scan src --include-examples

o1js-scan --version
```

Exit code is `1` when a finding at or above the `--fail-on` level (default
`high`) is present and `0` otherwise — so you can drop it straight into CI.
With the default, a low/medium finding (including the informational recipient
rule below) does **not** fail the build; use `--fail-on none` to only report,
or `--fail-on medium` to gate more strictly. A missing scan path exits `2` with
an error on stderr, so a typo can't silently pass CI as a clean run. Every run
prints a one-line summary (counts by severity and the gate verdict) to stderr.

**Test code is excluded by default — both backends.** Tests deliberately build
invalid values and bad transactions to prove the asserts reject them, so a
finding there is the point of the test rather than a circuit bug. A file counts
as test code when:

- its name matches `*.test.ts` / `*.spec.ts` (and the `.js`/`.jsx`/`.tsx`/`.mjs`
  /`.cjs` variants), or `*_test.nr` / `test_*.nr`;
- it sits under a `test/`, `tests/`, `__tests__/`, `spec/` or `__mocks__/`
  directory;
- (Noir only, content-based) the function carries a `#[test]` / `#[test(...)]`
  attribute, or sits inside a `mod test { … }` / `mod tests { … }` block —
  block-scoped, so a test module at the foot of a production file does not
  silence the rest of it.

Pass `--include-tests` to report them.

**Example code is downgraded, not dropped.** A finding in an `examples/` or
`example/` directory, or in a file named `*.eg.ts` (`.nr` and the other JS/TS
extensions too), is lowered to **LOW** with a note — still reported, no longer
able to fail a build. Example code is deliberately simplified, and flagging a
framework's own examples as vulnerabilities is noise; but it is *copied into
production* far more often than test code is, which is why it is downgraded
rather than hidden. Pass `--include-examples` to keep the original severity.

Whenever either policy applies, the run prints a line to **stderr** saying so —
e.g. `6 file(s) skipped as test code, 1 finding(s) downgraded as examples` — so
a quiet scan is never silently quiet. The counts also appear in SARIF under
`invocation.properties`. Note the trade-off: detection is **path-based only**
(no `describe(`/`it(` parsing), so a production circuit stored under `tests/`
*will* be skipped — the stderr line is how you notice.

**Directories skipped when walking a tree:** `node_modules`, `target` (nargo),
`.git`, `dist`, `build`, `__pycache__`, `.venv`, `venv`.

### Suppressing a reviewed finding

Silence a finding you've triaged without loosening the gate, with an inline
comment on — or on the line above — the flagged line:

```ts
this.send({ to, amount });  // o1js-scan-disable-line O1JS_UNCONSTRAINED_WITNESS

// o1js-scan-disable-next-line
this.send({ to, amount });
```

```nr
let inv = unsafe { hint(x) };  // o1js-scan-disable-line NOIR_UNCONSTRAINED_WITNESS
```

List one or more rule ids to suppress only those; a bare directive (no ids)
suppresses every rule on the target line.

As a library:

```python
from o1js_scan import analyze_file, analyze_project

for path, finding in analyze_project("src", lang="auto"):
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
      - uses: auditinfra-io/o1js-scan@v0.10.0
        with:
          path: src              # optional, defaults to the repo root
          lang: auto             # auto | o1js | noir
          # version: 0.10.0       # optional, pin the scanner version
          # fail-on-findings: true   # optional, fail the job on any high/critical
```

### Noir-only CI recipe

Recommended for Noir projects that want code-scanning alerts and a high-severity
gate:

```yaml
- uses: auditinfra-io/o1js-scan@v0.10.0
  with:
    path: .
    lang: noir
    fail-on-findings: true
```

Or without the Action:

```bash
pip install o1js-scan
noir-scan . --lang noir --fail-on high --sarif noir.sarif
```

### pre-commit (optional)

```yaml
# .pre-commit-config.yaml
- repo: local
  hooks:
    - id: noir-scan
      name: noir-scan
      entry: noir-scan
      language: system
      pass_filenames: false
      args: [".", "--lang", "noir", "--fail-on", "high"]
```

Inputs: `path` (default `.`), `lang` (`auto`|`o1js`|`noir`, default `auto`),
`version` (PyPI version to install, default latest), `upload-sarif` (default
`true`), `fail-on-findings` (default `false`), `include-tests` (default
`false`), `include-examples` (default `false`). Output: `sarif-file`. SARIF
upload needs `security-events: write` and code scanning enabled.

## What it detects (o1js)

| Rule | Severity | What it means |
|------|----------|---------------|
| `O1JS_MISSING_STATE_PRECONDITION` | high | `this.x.get()` read without a matching `requireEquals(...)` / `getAndRequireEquals()`. A bare `get()` adds **no** account precondition, so the proof doesn't bind `x` to its on-chain value — a prover can substitute any value. |
| `O1JS_UNCONSTRAINED_WITNESS` | high / medium | A `@method` argument (a prover-controlled private witness) flows into a `this.send` **amount** or a state `.set(...)` and is **never** asserted. Direct analog of an under-constrained Circom signal. High when it reaches a value transfer. |
| `O1JS_UNCONSTRAINED_PROVABLE_WITNESS` | high / medium / low | A `Provable.witness(...)` local flows into a send/state effect with **no** in-circuit assertion. The witness callback runs *outside* the circuit (it's only a prover hint), so the result is a fresh prover-controlled value — the other witness source besides `@method` args. It must be re-derived and asserted (`x.assertEquals(<recomputed>)`) or bound to state. High on a send amount, medium on a state write, low on a recipient. |
| `O1JS_UNCONSTRAINED_RECIPIENT` | low | A `@method` argument is used **only** as the `to:` recipient of `this.send(...)`. This is usually intended (a user names their own withdrawal destination) and is informational — it only matters if the destination is meant to be a fixed treasury or a state-recorded address. Does **not** trip the CI exit-code gate. |
| `O1JS_WITNESS_NOT_BOUND_TO_STATE` | medium | A witness is only *trivially* constrained (e.g. `> 0`, or compared against a constant) before an effect — never tied to on-chain state. Confirm the off-chain orchestration makes this safe, or the balance is drainable up to its standing value. |
| `O1JS_STALE_MERKLE_ROOT` | high | A method recomputes a Merkle root from a prover-supplied witness (`computeRootAndKey` / `calculateRoot`) but binds **none** of the recomputed roots to the current on-chain root. Without a `this.root.requireEquals(...)` / `assertEquals` against the live root, a prover can pass a witness for a fabricated or stale tree — forging membership or replaying old state. Binding may live in an undecorated same-class helper (`this.verifyX(witness)`); one level of helper propagation covers that. |
| `O1JS_UNVERIFIED_PROOF` | high | A `@method` parameter typed as `Proof<...>` / `SelfProof` / `DynamicProof` / `*Proof` is never `.verify()` / `.verifyIf()`'d. Passing a Proof does not verify it — without an explicit verify the prover can supply an arbitrary proof object, and any use of its `publicOutput` is unconstrained. |
| `O1JS_UNASSERTED_BOOL` | high / medium | An o1js predicate (`equals` / `lessThanOrEqual` / …) returns a `Bool` and adds **no** constraint unless the result is asserted or used. HIGH when the call is a bare discarded statement; MEDIUM when assigned to a local that is never referenced again. |
| `O1JS_UNCONSTRAINED_SENDER` | high / medium | `this.sender.getUnconstrained()` returns the tx sender without proving it. HIGH when that value (or a local from it) flows into an assert / state `.set` / `send` (vacuous check); MEDIUM otherwise. Prefer `this.sender.getAndRequireSignature()`, or the expanded idiom `AccountUpdate.createSigned(sender)`. **Stays quiet when** (1) the same `@method` also calls `this.sender.getAndRequireSignature()` anywhere (signature requirement is method-scoped), or (2) the witnessed sender value is the argument to `AccountUpdate.createSigned(...)` / an `AccountUpdate.create(...).requireSignature()` on that same key (argument identity required — a `createSigned` on a different key does not suppress). |
| `MissingRangeCheck` | high | A raw `Field` (not the range-checked `UInt64`/`UInt32`) is used as a transfer amount. A `Field` is an element mod p and is not range-bounded. |
| `O1JS_WEAK_PERMISSIONS` | high / medium | `editState` / `send` permission set to `proofOrSignature()` or `none()`, letting the zkApp account key bypass the circuit by signing. |

### False-positive guards (o1js)

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
  `publicOutput` / `publicInput`) are suppressed. The same applies to the
  canonical OffchainState wrapper `this.offchainState.settle(proof)` (the
  framework verifies inside `settle`). A hand-rolled `.settle(proof)` is
  **not** assumed to verify. The inverse case (proof-typed arg never verified
  and not OffchainState-settled) is reported as `O1JS_UNVERIFIED_PROOF`.
- **Asserted / used Bools are skipped.** A predicate chained with
  `.assertTrue()` / `.assertFalse()`, nested in `Provable.if(...)`, or
  assigned to a local that is later referenced, is not reported as
  `O1JS_UNASSERTED_BOOL`.
- **Authenticated senders are skipped.** `this.sender.getUnconstrained()`
  does not fire when the same `@method` also calls
  `this.sender.getAndRequireSignature()`, or when that witnessed value is
  passed to `AccountUpdate.createSigned(...)` / authenticated via
  `.requireSignature()` on an AccountUpdate built from it (argument
  identity required).
- Comments and string literals are stripped before analysis, so an `assert`
  inside a string can't create a false result.

## What it detects (Noir)

The same soundness idea — under-constrained witnesses — applies to
[Noir](https://noir-lang.org) (`.nr`) circuits. Point the scanner at `.nr`
files (or use `--lang noir`) and it analyzes them with the Noir rule set.
Same lexical, dependency-free approach. Calibrated against aztec-nr oracle /
`unsafe` idioms — see [`docs/noir_calibration.md`](docs/noir_calibration.md).

| Rule | Severity | What it means |
|------|----------|---------------|
| `NOIR_UNCONSTRAINED_WITNESS` | high | A value bound from an `unsafe { ... }` block — the result of an `unconstrained fn` (oracle / Brillig hint) — that is never re-constrained by an `assert` / `assert_eq` (or a confirming helper / merkle check). The hint runs **outside** the circuit. Analog of `O1JS_UNCONSTRAINED_PROVABLE_WITNESS`. |
| `NOIR_UNCONSTRAINED_INPUT` | medium | A private (witness) input of `fn main` that flows into **no** `assert` / `assert_eq` and is **not** part of the public output. Analog of `O1JS_UNCONSTRAINED_WITNESS`. |
| `NOIR_UNCONSTRAINED_PUBLIC_INPUT` | medium | A **public** input of `fn main` that reaches no constraint and no output — the circuit never reads it. The *dual* of the private-witness rule: the verifier supplies the value and believes the statement is about it, while the circuit ignores it (e.g. a `merkle_root: pub Field` that is never checked, so membership was never actually proven). MEDIUM because a deliberately unused public input is also a legitimate idiom for binding a proof to a context (nonce / chain id / recipient), which is indistinguishable lexically — so it does not gate CI at the default `--fail-on high`. |
| `NOIR_UNCHECKED_CAST` | medium | A prover-controlled value cast to a narrow unsigned type (`as u8`/`u16`/`u32`) with **no** range assertion. Analog of o1js `MissingRangeCheck`. |
| `NOIR_UNCONSTRAINED_ARRAY_INDEX` | medium | A prover-controlled value used as an array index (`arr[i]`) with **no** check of any kind on it. Noir's implicit bounds check establishes only that the index is *in range* — not that it is the *correct* index — so the prover stays free to select any element and still produce a verifying proof. This is the selector-freedom bug behind Merkle path positions, note selection and allow-list membership. Suppressed when the index is range-bounded, pinned by an equality, bounded before a cast (`index.assert_max_bit_size::<8>(); let i = index as u32;`), or when the value read back is itself pinned by an `assert_eq`. |
| `NOIR_UNASSERTED_BOOL` | high / medium | A comparison whose `bool` result is **discarded**. Analog of o1js `O1JS_UNASSERTED_BOOL`. |
| `NOIR_CONDITIONAL_ASSERT` | medium | An `assert` inside `if <flag> { ... }` where `<flag>` is a prover-controlled bare `bool`. |
| `NOIR_CONDITIONAL_CONSTRAIN` | medium | A `constrain_*` / `confirm_*` / `verify_*` call only under a prover-controlled `if`, while an `unsafe` hint still reaches the output. |
| `NOIR_UNUSED_CHECK_RESULT` | high / medium | A `check_*` / `confirm_*` / `verify_*` / `constrain_*` result is discarded (bare call) or assigned and never asserted — the check does not bind the circuit. |
| `NOIR_VACUOUS_CONSTRAINT` | high / medium | A constraint that is satisfied by construction: a self-comparison (`assert(x == x)`, `assert_eq(x, x)`, `x >= x`) or a constant condition (`assert(true)`). It adds no restriction, but the line *reads* as a check — which makes it more dangerous than a missing constraint, because review stops there. HIGH for a self-comparison (almost always a typo for a real check: `assert(computed == expected)` mistyped as `assert(expected == expected)`); MEDIUM for a constant, which is more often a placeholder. `x != x` is **not** flagged — that is unsatisfiable, a liveness bug rather than a silent soundness hole. |
| `NOIR_UNSAFE_MISSING_SAFETY` | low | An `unsafe { ... }` block with no adjacent `// Safety:` comment. Informational; does not fail CI at default `--fail-on high`. |

### False-positive guards (Noir)

- **Assert / let-hop / same-file confirm helpers** bind `unsafe` hints.
- **Call-site names** `constrain_*` / `confirm_*` / `verify_*` /
  `check_(non_)membership*` / `public_data_storage_read` credit args (with
  unused-result detection for discarded checks).
- **Documented intentional unconstrained** (requires adjacent `// Safety:`):
  `random()`, `avm::…`, and kernel/rollup/discovery deferred wording.
- **Tuple `let` + asserted flags** bind merkle witnesses passed into membership checks.

Example:

```console
$ noir-scan examples/noir_unconstrained.nr --include-examples
HIGH     NOIR_UNCONSTRAINED_WITNESS         noir_unconstrained.nr:16  fn=main  Unconstrained `unsafe` result `inv` in `main`
LOW      NOIR_UNSAFE_MISSING_SAFETY         noir_unconstrained.nr:16  fn=  `unsafe` block without a `// Safety:` comment
noir-scan: 2 finding(s) [1 high, 1 low] in 1 file(s) — fails (--fail-on high)

$ noir-scan examples/noir_constrained.nr --include-examples
noir-scan: no findings (or no Noir / o1js sources found)
```

As with the o1js example above, `--include-examples` is only needed because
these demo files live under `examples/`.

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

- **Unasserted-Bool detection is statement-shaped.** Tier A only flags bare
  expression statements whose outermost call is a Bool predicate with nothing
  chained after it. Predicates nested inside `Provable.if(...)`, or assigned
  and later used, are not flagged. Complex control-flow uses of a Bool local
  may still be missed if the name is never referenced (failure mode: miss,
  not a false positive).

- **Signature-gating is method-level and substring-based.**
  `_method_is_signature_gated` treats a whole `@method` as owner-gated if it
  contains a signature idiom, and it recognizes a verifier only when the
  receiver name literally contains `signature` — so `sig.verify(admin, msg)`
  is **not** recognized as gating, while an unrelated signature check elsewhere
  in a large method can over-suppress. It is all-or-nothing per method.

- **Sender authentication is name-based and same-method only.**
  `O1JS_UNCONSTRAINED_SENDER` suppresses when `this.sender.getAndRequireSignature()`
  or `AccountUpdate.createSigned(<that sender>)` appears in the **same** `@method`
  body. A signature requirement that lives only in a helper
  (`this.requireSenderSig()` → `getAndRequireSignature` inside) is **not**
  followed — failure mode is a false positive on correct code that wraps the
  idiom, not a missed real bug.

- **Noir cross-crate helpers** are recognized by **name convention** only (no
  `Nargo.toml` / import resolution). Prefer miss over false positive.

These are the reason findings are a starting point for human review, not
proofs. A dataflow-aware rewrite is deliberately out of scope for the
lexical analyzer.

## Where this tool stops

o1js-scan is deliberately a **shallow, single-file lexical pass** — no parser,
no dataflow, no solver. That is what makes it dependency-free and instant in
CI, and it is also a hard ceiling. The limitations above aren't a backlog;
they're consequences of the design.

So it is worth being explicit about what this tool can and cannot tell you:

- **A clean run is not an audit.** It means no *shape* this scanner recognizes
  matched — not that the circuit is sound. Bug classes that need dataflow,
  path sensitivity, or constraint solving are out of reach for a tool of this
  shape, in any language.
- **A finding is a lead, not a verdict.** Every rule here is a heuristic with
  a documented false-positive class.

That trade is the right one for a linter you run on every commit. If you're
working on something where the difference matters — a protocol holding real
value, a circuit you can't afford to get wrong — treat this as the first pass
and budget for a real review.

Deeper analysis is what [Proofplay Logic](https://github.com/auditinfra-io)
works on; this scanner is the part of it we can give away. If you want a
circuit looked at properly, reach out: `auditinfracorp@proton.me`.

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

Noir analysis targets Noir syntax used by Aztec / nargo projects (`.nr`); it
does not invoke `nargo` or compile circuits.

## How it works

It's a lexical analyzer, not a full TypeScript or Noir parser — o1js and Noir
sources are brace-delimited and regex-tractable, and the output is meant to be
triaged by a human. That keeps it dependency-free and instant to run in CI.
Findings are a starting point for review, not proofs.

## Roadmap / contributing

Contributions welcome — new rule families, more FP guards, and real-world
calibration archetypes are all valuable. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
Run the tests and linter with:

```bash
pip install -e ".[dev]"
pytest          # unit tests + Noir/o1js corpus
ruff check .    # lint
npm run format:check   # prettier, npm wrapper only
```

## License

Apache-2.0. See [`LICENSE`](LICENSE).
