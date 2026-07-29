# Changelog

All notable changes to o1js-scan are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- **The npm publish step could never run.** `publish-npm` invoked
  `python -m pytest tests/test_packaging.py` with no install step;
  `actions/setup-python` provides a bare interpreter, so on the first release
  that reached it the job died in under a second with `No module named pytest`
  and the npm upload was skipped. The step had been written, committed and
  shipped without ever executing — the same "capability that exists but is
  never reached" defect this analyzer looks for, in the pipeline that ships the
  analyzer. Adds `pip install -e ".[dev]"` before it.
- `tests/test_workflow_sanity.py` — static checks over `.github/workflows/`:
  no job may invoke a Python tool it never installed (per-job, since each job
  gets a fresh runner and `needs:` installs nothing), every registry-uploading
  job must depend on `preflight`, and a release must still target both
  registries. Workflow steps are the least-tested code in the repo — they run
  only on the event that triggers them, which for this one is a real release.

## [0.11.0] - 2026-07-29

### Added
- **`scripts/bump_version.py`** — sets the version in all three manifests at
  once and refuses anything that is not plain `X.Y.Z` (npm rejects PEP 440
  suffixes like `1.0.0rc1`). `--check` verifies they agree.
- **A `preflight` job gates both uploads.** It compares the manifests to each
  other and to the release tag, and fails the whole run — with a message naming
  the fix — if they disagree. `skip-existing: true` on the PyPI upload makes
  re-running a release idempotent, which is safe precisely because `preflight`
  has already proven the version matches the tag.
- **npm publishing is now wired.** `publish.yml` gains a `publish-npm` job that
  publishes the Node wrapper alongside the PyPI upload, with `--provenance` so
  the tarball carries a signed attestation linking it to the commit and workflow
  that built it. Requires an `NPM_TOKEN` repository secret (an npm *automation*
  token). Before the upload it re-checks manifest version consistency and
  installs the packed tarball into a scratch project to run the real binary, so
  a broken `files` glob fails the release instead of shipping.
- **Prettier config and CI gate** (`.prettierrc.cjs`, `npm run format` /
  `format:check`), mirroring o1js's own options. Required by o1js's
  community-package guidance. Covers only the Node wrapper and its smoke test —
  the analyzer is Python and stays on ruff.
- **`o1js` declared as an optional peer dependency**, satisfying the o1js
  community-package requirement while staying truthful: the analyzer never
  imports o1js, and `noir-scan` runs against Noir projects that have no o1js in
  the tree at all. A mandatory peer dep would be auto-installed by npm ≥7 for
  every Noir-only user.
- `docs/o1js_community_listing.md` — a prepared, unsubmitted draft for adding
  o1js-scan to the o1js community packages list, including the two requirements
  we do not meet and why.
- **Documentation is now tested.** `tests/test_readme_examples.py` executes every
  README console transcript and compares real output;
  `tests/test_docs_consistency.py` derives the rest from the source of truth —
  the rule tables against the rule ids the analyzer actually emits (**both**
  directions, so neither a phantom rule nor an undocumented one can survive),
  the skipped-directory list against `_SKIP_DIR_NAMES` (whose code comment asked
  a human to keep the README in sync and was enforced by nobody), the GitHub
  Action inputs against `action.yml`, and any stated test count against the real
  one. Each guard carries a vacuity check, since a doc test that parses nothing
  passes unconditionally.
- `tests/test_packaging.py` pinning the manifest fixes below.
- **`NOIR_UNCONSTRAINED_ARRAY_INDEX`** (MEDIUM) — a prover-controlled value used
  as an array index with no check of any kind on it. Noir's implicit bounds
  check proves the index is *in range*, never that it is the *correct* index, so
  the prover stays free to select any element and still verify — the
  selector-freedom bug behind Merkle path positions, note selection and
  allow-list membership. Deliberately framed as soundness, not as the
  completeness/"proof failure" argument the equivalent rule elsewhere uses.
  Suppressed when the index is range-bounded, pinned by an equality, bounded
  before a cast, or when the value read back is itself pinned by `assert_eq`.
  Measured across all ten pinned Noir repos: **one** new finding
  (`noir_json_parser` `keymap.nr`, classified UNREVIEWED), zero elsewhere, no
  pre-existing finding changed. One FP found and fixed during the pass rather
  than accepted. Known recall gap — a range bound alone does not make a selector
  sound but is suppressed for precision — is recorded in
  `docs/noir_calibration.md`. Three paired mutation fixtures.

### Fixed
- **`npm install -D o1js-scan` did not work — the package had never been
  published.** The README instructed it in three places and CI had smoke-tested
  `bin/o1js-scan.js` on every run, but no workflow ever published to npm and the
  registry returned `{"error":"Not found"}` for the name. Built, tested,
  documented, never shipped.
- **Version drift across packaging manifests.** `package.json` said `0.9.0`
  while `pyproject.toml` and `o1js_scan/__init__.py` said `0.10.0`. Verified by
  installing the packed tarball: `npm install o1js-scan@0.9.0` produced a binary
  whose `--version` printed `0.10.0`, and which would have stamped `0.10.0` into
  the `toolVersion` of every SARIF report a consumer archived. Now pinned by a
  test and re-checked in the release workflow against the tag.
- **The Noir example in the README did not reproduce either** — the same
  defect, found by auditing the rest of the file after fixing the o1js one. It
  was documented as `noir-scan examples/noir_unconstrained.nr  # HIGH
  NOIR_UNCONSTRAINED_WITNESS`; the real output was LOW at exit 0, and it also
  omitted the second finding (`NOIR_UNSAFE_MISSING_SAFETY`) the file produces.
  It survived the first pass because it sat in a ` ```bash ` block while the
  new guard read only ` ```console ` blocks; the guard now covers both.
- **`pytest  # 154 tests`** in the README, long after the suite reached 257.
  The count is gone; a test now enforces that any count stated in the docs is
  accurate, without requiring one.
- **`.gitignore` did not cover generated artifacts** — `node_modules/`,
  `*.tgz` from `npm pack`, and `*.sarif`. The last one matters: `--sarif`
  defaults to `./o1js-scan.sarif`, so running the scanner inside its own
  checkout staged a report.
- **A release could be cut without bumping the version.** `v0.11.0` was tagged
  while all three manifests still said `0.10.0`, because tagging changes none of
  them. The npm gate caught it (`package.json version 0.10.0 != release tag
  0.11.0`) but PyPI only failed downstream, as `400: File already exists
  ('o1js_scan-0.10.0-py3-none-any.whl')` — a symptom several steps from the
  cause. Nothing shipped to either registry. Both jobs now share one `preflight`
  check that names the actual problem, `scripts/bump_version.py` makes the bump
  a single command, and `CONTRIBUTING.md` documents the order (bump, commit,
  then tag).
- **The README's headline example did not reproduce.** It showed
  `o1js-scan examples/vulnerable_vault.ts` reporting `HIGH` and exiting `1`; the
  real output was `[2 low]`, "passes", exit `0`. The demo file lives under
  `examples/`, which the path classifier deliberately downgrades so a project's
  own sample code cannot fail its build — the flagship demo was tripping the
  tool's own suppression. The transcript now passes `--include-examples` and
  explains why. The neighbouring claim that `examples/safe_vault.ts` "scans
  clean" was also wrong: it reports one LOW. Both transcripts are now executed
  by tests.
- **Constraint-absence rules no longer fire inside `unconstrained fn` bodies.**
  Brillig code runs outside the circuit and emits no constraints, so a rule
  whose premise is "a constraint that should exist is missing" cannot apply
  there — a narrowing cast is not missing a range check when there is no
  circuit to under-constrain. This was the systematic FP class identified (and
  deferred) in 0.10.0; `noir_json_parser` MEDIUM 2 → 0, no other corpus change.
  Implemented as an explicit deny-list so a future rule defaults to firing
  inside unconstrained code rather than being silently hidden, and bounded by a
  paired mutation fixture whose twins differ only by the `unconstrained`
  keyword. Soundness of a Brillig hint is still checked where it belongs — at
  the caller's `unsafe { ... }` site.

## [0.10.0] - 2026-07-26

### Added
- **Test-context suppression for o1js** (parity with Noir). `*.test.ts`,
  `*.spec.ts` (+ js/jsx/tsx/mjs/cjs), and any `test/`, `tests/`, `__tests__/`,
  `spec/` or `__mocks__/` directory are skipped by default. `--include-tests`
  now applies to **both** backends.
- **Example-code downgrade** (both backends). Findings in `examples/` /
  `example/` directories or `.eg.` filenames are lowered to **LOW** with a note
  rather than dropped — example code is copied into production more often than
  test code is. `--include-examples` keeps the original severity.
- **Skipped-file transparency.** The CLI prints a stderr line whenever the path
  policy applied (e.g. `6 file(s) skipped as test code, 1 finding(s) downgraded
  as examples`), and the counts appear in SARIF `invocation.properties`. Silent
  suppression was previously invisible.
- **`scripts/mina_canary.sh`** — the o1js side had no canary, so those rules
  (the only ones with confirmed real-world findings) could regress silently.
  Twelve pinned repos, gated on classified budgets **in both directions**: a new
  unclassified HIGH fails, and so does a *lost* confirmed true positive.
  Weekly `mina-canary` CI job.
- **`docs/mina_calibration.md`** — all 32 Mina findings classified TP/FP/
  UNREVIEWED with reasoning, matching the Noir acceptance criterion.
- Pinned regression fixtures for the confirmed wild true positives
  (`tests/corpus/o1js/tp_regression_*.ts`) plus an o1js corpus harness.
- New public API: `ScanStats`, `is_test_path`, `is_example_path`;
  `include_examples` / `stats` parameters on `analyze_file` / `analyze_project`.
- Package authorship and maintainer metadata (Dan / Proofplay Logic) and a
  contact address in the README handoff.
- README "Where this tool stops" section — states plainly that a clean run is
  not an audit and a finding is a lead, not a verdict, and points readers who
  need analysis beyond a lexical pass to where that work happens.

### Fixed
- `docs/noir_calibration.md` promised every finding was classified but left the
  2 `noir_json_parser` MEDIUMs unreviewed. Both are now classified **FP**: the
  casts sit inside `unconstrained fn search_for_key_in_map`, and unconstrained
  code emits no constraints, so a narrowing cast there cannot be missing a range
  check. This is a **systematic FP class** (`NOIR_UNCHECKED_CAST` does not check
  whether its enclosing function is `unconstrained`), documented for a later fix
  rather than retuned in this pass.
- README documented `--include-examples` and both-backend test suppression;
  `action.yml` gained `include-tests` / `include-examples` inputs, without which
  the Action could not reach either behaviour.

## [0.9.0] - 2026-07-26

### Added
- **`NOIR_VACUOUS_CONSTRAINT`** (high/medium) — a constraint satisfied by
  construction: a self-comparison (`assert(x == x)`, `assert_eq(x, x)`,
  `x >= x`, `x.assert_eq(x)`) or a constant condition (`assert(true)`). It
  binds nothing while *reading* as a check, so review stops there — more
  dangerous than a missing constraint. HIGH for self-comparison (a typo for a
  real check), MEDIUM for a constant (often a placeholder). `x != x` is
  deliberately not flagged: unsatisfiable is a liveness bug, not a silent
  soundness hole. Validated across **4,911 real assert call sites** in the ten
  corpus repos with zero false positives; mutating the real reconstruction
  check in noir_json_parser's `slice_field` from `assert(total == f)` to
  `assert(total == total)` makes it fire
  (`fp_`/`tp_jsonparser_real_assert.nr`).
- **`NOIR_UNCONSTRAINED_PUBLIC_INPUT`** (medium) — a new detection axis rather
  than another suppression heuristic. Every prior rule asks "is this *private*
  witness constrained?"; public inputs were explicitly skipped on the
  assumption that they are "already bound". That assumption is wrong as a
  security claim: a public input that reaches no constraint and no output means
  the proof asserts nothing about it, so a verifier checking a proof against
  (say) an unused `merkle_root: pub Field` believes membership was proven when
  it was not — the dual of an under-constrained witness.
  Deliberately MEDIUM: an unused public input is also a legitimate idiom for
  binding a proof to a context (nonce / chain id / recipient), which is
  lexically indistinguishable, so the rule does not gate CI by default.
  Validated by mutating a real zkpassport circuit — silent on the original,
  fires on the variant with the commitment check removed
  (`fp_`/`tp_zkpassport_pub_comm.nr`). Zero findings across all ten corpus
  repos, including ~780 real circuit entry points in zkpassport/circuits.

## [0.8.0] - 2026-07-25

### Changed
- **Noir test code is no longer scanned by default.** This is a behaviour
  change: findings in `*_test.nr` / `test_*.nr` files, under `test/` or
  `tests/` directories, in `#[test]` functions, or inside `mod test`/`mod tests`
  blocks are suppressed. Pass `--include-tests` (or `include_tests=True` to
  `analyze_project` / `analyze_file` / `analyze_noir_file`) to restore them.

### Fixed
- **Noir false positives on a second corpus** (eight noir-lang / zkEmail
  libraries; 9 HIGH → 0, all nine read and classified as FPs in
  `docs/noir_calibration.md`):
  - Test code is excluded by default — detected by filename (`*_test.nr`,
    `test_*.nr`, `test/` or `tests/` path segment), a `#[test]` /
    `#[test(...)]` attribute, or an enclosing `mod test`/`mod tests` block
    (block-scoped). New `--include-tests` flag restores those findings.
  - Constraint seeding now recognizes the whole **assert family** — any call
    whose name contains `assert`, with optional turbofish
    (`assert_max_bit_size::<240>(`, `assert_lt(`, `sortfn_assert(`) — and for
    the method form `<receiver>.assert_xxx(...)` seeds the **receiver**
    expression, so `lt_parameter.assert_max_bit_size::<240>()` and
    `chunks[0].assert_max_bit_size::<8>()` bind their values.
  - Type-annotated `let` bindings (`let raw: Field = …`) now participate in the
    constraint fixpoint; previously they were invisible, orphaning a hint from
    the assert that bound it.
  - aztec-nr regression delta: HIGH unchanged at 0; MEDIUM 4 → 0 (all four were
    `NOIR_UNUSED_CHECK_RESULT` in a test file). zkpassport unchanged.

### Added
- `scripts/noirlang_canary.sh` — second FP canary over eight pinned noir-lang /
  zkEmail repos, gated on per-repo *classified budgets* rather than a bare
  zero-HIGH assertion, plus a weekly `noirlang-canary` CI job.
- Paired mutation fixtures (`fp_`/`tp_` twins) for each fix, and a `@scan-as`
  corpus annotation so fixtures under `tests/` can be analyzed as production
  code (or opt into a test-shaped path).
- Ruff lint configuration (`[tool.ruff]`) and a `lint` CI job; the codebase
  passes `ruff check .` clean.
- `py.typed` marker (PEP 561) so downstream type checkers see the package's
  type hints; `Typing :: Typed` and per-version Python classifiers.
- `Repository` and `Changelog` project URLs.

### Changed
- README: added a table of contents and a runnable example with real output.

## [0.7.1] - 2026-07-25

### Fixed
- **ZKPassport circuits FP retune** (calibrated on `zkpassport/circuits@d3a75ac`):
  767 → 321 findings; **0 HIGH / 0 MEDIUM** (remaining are LOW missing-Safety
  hygiene). Tuple-`let` fixpoint for private `main` inputs; cross-module
  `check_*` call-site binders; deferred Safety for ASN.1 length / re-verify /
  hash-nonce wording; `assert(index != -1)` found-sentinel before `as u32`;
  dead (unread) `unsafe` bindings no longer HIGH. Corpus fixtures
  `fp_zkpassport_*.nr`. aztec-nr canary still 0 HIGH.

## [0.7.0] - 2026-07-25

### Added
- **Noir productization** — dual-brand docs/CLI; `noir-scan` console-script alias;
  `--lang {auto,o1js,noir}`; skip `target/` / `.git` / build dirs; GitHub Action
  `lang` input; Noir CI recipe + optional pre-commit snippet in README.
- **`NOIR_UNUSED_CHECK_RESULT`** (high/medium) — `check_*` / `confirm_*` /
  `verify_*` / `constrain_*` result discarded (bare call) or assigned and never
  asserted.
- **`NOIR_CONDITIONAL_CONSTRAIN`** (medium) — constrain/confirm/verify only under
  a prover-controlled `if`, while an `unsafe` hint still reaches the output.
- Annotated Noir recall corpus (`tests/corpus/noir/`) + `docs/noir_calibration.md`
  (aztec-nr 21→0 HIGH story) + optional weekly/manual aztec-nr canary workflow.

### Changed
- Same-file helper credit for `unsafe` hints is **assert-only** (hollow
  `confirm_*` that only returns the hint no longer suppresses the caller).
- Cross-module name credit skips same-file helpers that are not assert-crediting.
- Multi-line `// Safety:` adjacency widened (aztec-nr notes); split-line
  `let x =` / `unsafe` Safety adjacency.
- CONTRIBUTING documents the NoirLexer path.

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

[Unreleased]: https://github.com/auditinfra-io/o1js-scan/compare/v0.10.0...HEAD
[0.10.0]: https://github.com/auditinfra-io/o1js-scan/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/auditinfra-io/o1js-scan/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/auditinfra-io/o1js-scan/compare/v0.7.1...v0.8.0
[0.7.1]: https://github.com/auditinfra-io/o1js-scan/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/auditinfra-io/o1js-scan/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/auditinfra-io/o1js-scan/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/auditinfra-io/o1js-scan/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/auditinfra-io/o1js-scan/releases/tag/v0.4.0
[0.3.0]: https://github.com/auditinfra-io/o1js-scan/releases/tag/v0.3.0
[0.2.0]: https://github.com/auditinfra-io/o1js-scan/releases/tag/v0.2.0
[0.1.0]: https://github.com/auditinfra-io/o1js-scan/releases/tag/v0.1.0
