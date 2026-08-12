# Request to bring `o1js-scan` into the o1js repository

Thank you for listing [`o1js-scan`](https://github.com/auditinfra-io/o1js-scan)
under o1js Community Packages. Since the listing was proposed on July 30, 2026,
the scanner has moved from v0.13.0 to v0.15.0. I would like to explore a closer,
first-party integration in the o1js repository—not merely a more prominent
directory entry.

I would love for `o1js-scan` to live in the o1js repository itself, with the
o1js-specific scanner maintained as part of the project rather than only linked
as a community package. I am open to transferring the relevant implementation
or adapting it to the repository's architecture and governance. A non-blocking
CI integration could be a low-risk first use while the team evaluates its
signal; it could run against relevant TypeScript sources and upload SARIF
without making every finding a merge blocker or an official vulnerability.

### What changed since the Community Packages review

#### v0.14.0: semantic witness-flow analysis and explainable results

- A new dependency-free semantic layer follows prover-controlled values through
  typed aliases and same-contract helper calls into state writes and transfers.
  It computes inter-procedural summaries while keeping facts scoped to the
  correct contract and preserving compound-constraint identity.
- `--explain` now shows the observed source-to-sink path in terminal output.
  SARIF reports carry the same provenance as `codeFlows`, so a reviewer can see
  why the analyzer connected a witness to an effect instead of receiving an
  opaque regex match.
- The npm release path is exercised on every CI run: it installs the packed
  tarball in a scratch project, verifies the version, and checks that a known
  vulnerable fixture produces the expected finding.

#### v0.15.0: current o1js syntax and continuous upstream compatibility

- The parser now recognizes `@method()`, typed and declaration-only `@state`
  fields, multiline decorators, nested callback-shaped parameter types,
  TypeScript access modifiers, and aliases wrapped in parentheses or `as Type`.
- Equivalent constraints are normalized across instance
  `assertEquals(...)`, static `Provable.assertEqual(...)`, and
  `equals(...).assertTrue()` forms.
- Low-level `AccountUpdate.balance.subInPlace(...)` debits are recognized as
  transfer effects, including when they occur in block- or expression-bodied
  prover callbacks. Security logic in those callbacks is reported as logic
  outside the proof.
- A scheduled compatibility canary clones the current public o1js repository,
  scans its TypeScript syntax, validates every JSONL record, and rejects an
  empty report so a vacuous green run cannot hide parser drift.
- Privacy guidance now states the operational boundary explicitly: the CLI is
  local, has no telemetry or upload step, and has no third-party Python runtime
  dependencies. A separate guide explains how to submit synthetic reproducers
  without disclosing private application code.

### Evidence behind the request

- The o1js rule set is calibrated against 14 pinned public Mina repositories.
  Its checked-in classifications include confirmed examples of an unasserted
  `Bool`, an unverified recursive proof, an unconstrained sender, a vacuous
  self-assertion, and weak upgrade permissions. Confirmed high-severity shapes
  are retained as regression fixtures, and the canary fails if they disappear.
- The scanner covers all 15 rules documented in the README, including missing
  state preconditions, unconstrained method and `Provable.witness` values,
  stale Merkle roots, unverified proofs, discarded predicates, unconstrained
  senders, weak permissions, and security logic outside the proof.
- It is Apache-2.0, emits SARIF 2.1.0, supports inline suppressions, skips test
  code by default, and downgrades examples rather than silently hiding them.
- It has no runtime dependency on o1js and analyzes source without compiling or
  executing contracts. That makes an advisory trial isolated and inexpensive.
- The npm package uses a thin Node wrapper and requires Python 3.8+ on `PATH`.
  The analyzer itself has no third-party Python runtime dependencies.

These points are evidence of useful engineering and calibration, not a claim
of completeness. `o1js-scan` is a deliberately lightweight static analyzer; a
clean run is not an audit, and every finding still requires review.

Would the team be open to bringing the o1js-specific scanner into the o1js
repository? I am happy to contribute the integration, handle the initial result
triage, and work within the ownership and contribution model the team prefers.

### Relevant links

- [Source and documentation](https://github.com/auditinfra-io/o1js-scan)
- [v0.13.0...v0.15.0 comparison](https://github.com/auditinfra-io/o1js-scan/compare/v0.13.0...v0.15.0)
- [Changelog](https://github.com/auditinfra-io/o1js-scan/blob/main/CHANGELOG.md)
- [Mina calibration](https://github.com/auditinfra-io/o1js-scan/blob/main/docs/mina_calibration.md)
- [Missing-constraint taxonomy](https://github.com/auditinfra-io/o1js-scan/blob/main/docs/missing-constraint-taxonomy.md)
- [Privacy model](https://github.com/auditinfra-io/o1js-scan/blob/main/docs/privacy.md)
- [npm package](https://www.npmjs.com/package/o1js-scan)
