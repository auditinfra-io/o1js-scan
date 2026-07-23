# Changelog

All notable changes to o1js-scan are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/auditinfra-io/o1js-scan/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/auditinfra-io/o1js-scan/releases/tag/v0.4.0
[0.3.0]: https://github.com/auditinfra-io/o1js-scan/releases/tag/v0.3.0
[0.2.0]: https://github.com/auditinfra-io/o1js-scan/releases/tag/v0.2.0
[0.1.0]: https://github.com/auditinfra-io/o1js-scan/releases/tag/v0.1.0
