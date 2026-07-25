# Changelog

All notable changes to o1js-scan are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.0] - 2026-07-25

### Added
- **Experimental Noir (`.nr`) support** — a whole new language.
  `analyze_file` / `analyze_project` now dispatch by extension: `.nr` files are
  analyzed as Noir circuits, `.ts`/`.js`/`.mjs` as o1js. New rules:
  - `NOIR_UNCONSTRAINED_WITNESS` (high) — an `unsafe { ... }` result (an
    unconstrained oracle / Brillig hint) never re-constrained by `assert` /
    `assert_eq`. Follows one `let` hop. Analog of
    `O1JS_UNCONSTRAINED_PROVABLE_WITNESS`.
  - `NOIR_UNCONSTRAINED_INPUT` (medium) — a private `fn main` input that
    reaches neither a constraint nor the public output (reachability taken to
    a fixpoint through `let` bindings). Analog of `O1JS_UNCONSTRAINED_WITNESS`.
  - `NOIR_UNCHECKED_CAST` (medium) — a prover-controlled value (private input
    or `unsafe` result) cast to a narrow unsigned type (`as u8`/`u16`/`u32`)
    with no range assertion; the cast truncates. Analog of o1js
    `MissingRangeCheck`.
  - `NOIR_UNASSERTED_BOOL` (high/medium) — a comparison whose `bool` result is
    discarded (a bare `x == y;` statement, or a `let` bound to a comparison and
    never used); comparisons add no constraint on their own. Analog of o1js
    `O1JS_UNASSERTED_BOOL`.
  - `NOIR_CONDITIONAL_ASSERT` (medium) — an `assert` gated by a prover-controlled
    bare `bool` condition (`if flag { assert(...) }`), which the prover can skip
    by setting the flag false. Scoped to bare witness bools.
  - `NOIR_UNSAFE_MISSING_SAFETY` (low) — an `unsafe` block missing a
    `// Safety:` comment.
  - New public API: `NoirLexer`, `analyze_noir_file`, `is_noir_source`,
    `NOIR_ORIGIN_TIER`; env kill-switch `AUDIT_NOIR_LEXER=0`.
  - `examples/noir_unconstrained.nr` (vulnerable) and `noir_constrained.nr`
    (fixed).
- New o1js rules:
  - `O1JS_UNVERIFIED_PROOF` (high) — a `@method` parameter typed as `Proof<...>`
    / `SelfProof` / `DynamicProof` / `*Proof` that is never `.verify()`'d;
    passing a proof does not verify it, so its `publicOutput` is unconstrained.
  - `O1JS_UNASSERTED_BOOL` (high/medium) — an o1js predicate
    (`equals`/`lessThanOrEqual`/…) whose `Bool` result adds no constraint unless
    asserted or used; high when discarded, medium when assigned but unused.
  - `O1JS_UNCONSTRAINED_SENDER` (high/medium) — `this.sender.getUnconstrained()`
    returns the sender without proving it; flagged when that value flows into an
    assert / state `.set` / `send`. Prefer `getAndRequireSignature()`.

### Fixed
- Cross-method binding false positives: a witness bound in an undecorated
  same-class helper is now recognized, with auth-suppression refinements for the
  sender / proof rules.

## [0.5.0] - 2026-07-24

### Added
- `--fail-on LEVEL` to configure the exit-code gate
  (`critical|high|medium|low|none`; default `high`). `none` never fails the run.
- `--version` flag.
- Inline suppressions: `// o1js-scan-disable-line [RULES]` and
  `// o1js-scan-disable-next-line [RULES]`. A bare directive suppresses every
  rule on the target line; otherwise only the listed rule ids.
- One-line stderr summary reporting per-severity counts, the number of files
  with findings, and the gate verdict.
- `SECURITY.md`, this `CHANGELOG.md`, and an `examples/` directory with a
  vulnerable contract and its fixed counterpart.
- Release workflow (`.github/workflows/publish.yml`) that builds an sdist +
  wheel and publishes to PyPI when a GitHub Release is published.

## [0.4.0] - 2026-07-23

### Added
- SARIF 2.1.0 output (`--sarif [FILE]`, `-` for stdout) for GitHub code scanning.
- Composite GitHub Action (`action.yml`) for one-step CI adoption.

## [0.3.0] - 2026-07-23

### Added
- `O1JS_STALE_MERKLE_ROOT` rule — flags a recomputed Merkle root from a
  prover-supplied witness that is never bound to the on-chain root.

## [0.2.0] - 2026-07-23

### Added
- `O1JS_UNCONSTRAINED_PROVABLE_WITNESS` rule — flags a `Provable.witness(...)`
  local that flows into an effect with no in-circuit assertion.

## [0.1.0] - 2026-07-23

### Added
- Initial release: lexical, dependency-free o1js / Mina zkApp soundness
  analyzer with rules for missing state preconditions
  (`O1JS_MISSING_STATE_PRECONDITION`), unconstrained method witnesses
  (`O1JS_UNCONSTRAINED_WITNESS`, `O1JS_WITNESS_NOT_BOUND_TO_STATE`), raw-`Field`
  transfer amounts (`MissingRangeCheck`), and weak account permissions
  (`O1JS_WEAK_PERMISSIONS`). JSON output and CI-friendly exit codes.

### Changed
- Hardened the regex scanners with bounded quantifiers so a crafted or
  minified input file cannot drive the analyzer into quadratic backtracking.
- The CLI exits `2` with an error when the scan path does not exist, instead
  of silently reporting zero findings.
- Lowercased the `critical` severity value so JSON output is case-consistent.
- Documented o1js **1.x and 2.x** compatibility.

### Fixed
- No longer flags a prover-chosen `to:` send recipient as a high-severity
  unconstrained witness; it is reported as a low, informational
  `O1JS_UNCONSTRAINED_RECIPIENT` that does not fail CI.
- State-derived ordering comparisons (`amount.assertLessThanOrEqual(bal)` and
  the chained `amount.lessThanOrEqual(bal).assertTrue()` form) are now
  recognized as binding a witness to on-chain state.

[Unreleased]: https://github.com/auditinfra-io/o1js-scan/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/auditinfra-io/o1js-scan/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/auditinfra-io/o1js-scan/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/auditinfra-io/o1js-scan/releases/tag/v0.4.0
[0.3.0]: https://github.com/auditinfra-io/o1js-scan/releases/tag/v0.3.0
[0.2.0]: https://github.com/auditinfra-io/o1js-scan/releases/tag/v0.2.0
[0.1.0]: https://github.com/auditinfra-io/o1js-scan/releases/tag/v0.1.0
