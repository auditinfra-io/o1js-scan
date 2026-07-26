# Contributing to o1js-scan

Thanks for helping make o1js zkApps and Noir circuits safer. Contributions of
new rule families, false-positive guards, and real-world calibration archetypes
are all welcome.

## Development setup

```bash
git clone https://github.com/auditinfra-io/o1js-scan
cd o1js-scan
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest
```

No third-party runtime dependencies — please keep it that way. The only test
dependency is `pytest`.

## Ground rules

- **Every rule change needs a test.** Add both a positive case (the rule fires)
  and at least one negative case (a false-positive guard) to `tests/`.
- **Stay quiet on correct code.** A new rule that produces noise on idiomatic
  o1js or Noir (including aztec-nr) is worse than no rule. When in doubt, prefer
  a false negative (miss) over a false positive — this tool's output is meant to
  be trusted enough to triage.
- **Lexical, not a full parser.** The analyzer is deliberately regex/brace-based
  so it stays dependency-free and instant. New rules should fit that model.
- **Findings are leads, not proofs.** Descriptions should tell a reviewer what to
  check and why, not assert that a bug definitely exists.

## Adding an o1js rule

1. Add the detection method to `O1jsLexer` in `o1js_scan/lexer.py`.
2. Give it a stable `rule_id` and a clear `title` + `description`.
3. Add tests to `tests/test_lexer.py` covering the positive case and the FP guards.
4. Document the rule in the o1js table in `README.md`.

## Adding a Noir rule

1. Add the detection method to `NoirLexer` in `o1js_scan/noir.py` and wire it from
   `NoirLexer.analyze`.
2. Give it a stable `rule_id` prefixed with `NOIR_` and a clear `title` +
   `description`. Prefer failure mode **miss** over **false positive** when
   adding suppressions (Safety notes, confirm/verify helpers, etc.).
3. Add tests to `tests/test_noir.py` (positive + FP guards). If the rule belongs
   in the recall corpus, also add an annotated fixture under
   `tests/corpus/noir/` (`// @recall-rule NOIR_…`).
4. Document the rule in the Noir table in `README.md`.
5. Re-check aztec-nr-shaped FP fixtures stay quiet (see `docs/noir_calibration.md`).

## Merging pull requests

**Use squash (or rebase) merges, not merge commits.**

A GitHub merge commit is authored by `GitHub <noreply@github.com>` — GitHub sets
that server-side and it cannot be changed after the fact. Squashing keeps every
commit on `main` attributed to whoever actually wrote it, and keeps history
linear.

This is not retroactively fixable on the existing history: the `v0.8.0`,
`v0.9.0` and `v0.10.0` tags all point at merge commits, and those tags are what
CI built the published PyPI artifacts from. Rewriting them would orphan the
released versions from `main`'s history — a real cost for a cosmetic gain. Fix
it going forward only.

Set **Settings → General → Pull Requests → Allow squash merging** (and untick
"Allow merge commits") to enforce this at the repository level.

## Reporting issues

Please include a minimal o1js or Noir snippet that reproduces the false positive
or missed detection — that's the fastest path to a fix and it usually becomes the
regression test.

For false positives specifically, use the **False-positive report** issue
template — it asks for exactly what a calibration fix needs (the snippet, the
finding, and why the flagged pattern is intended design).

## License

By contributing you agree that your contributions are licensed under Apache-2.0.
