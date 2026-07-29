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

If you touch the npm wrapper (`bin/`, `tests/npm/`), also run:

```bash
npm run format:check    # prettier; `npm run format` to fix
npm run test:npm-wrapper
```

Both run in CI. Prettier is fetched via `npx` on demand, so there is nothing to
install and no `node_modules` in a normal Python-only workflow.

## Documentation is tested

`tests/test_readme_examples.py` and `tests/test_docs_consistency.py` execute the
README's claims rather than trusting them: every console transcript is run and
compared, the rule tables are checked against the rule ids the analyzer actually
emits (both directions), and the skipped-directory list, GitHub Action inputs and
any stated test count are derived from the source of truth.

This exists because all of those had drifted. The headline example claimed a
`HIGH` and exit `1` while really producing `LOW` and exit `0` — the demo file
lives under `examples/`, which the path classifier downgrades, so the flagship
transcript was tripping the tool's own suppression.

Practical consequences when you change behaviour:

- Add a rule → add it to the matching README table, or `test_docs_consistency`
  fails. Remove one → remove it from the table too.
- Change output format, severities, or the example fixtures → re-run the
  README transcripts and paste the **real** output. Do not hand-edit it.
- Quoting a test count anywhere in the docs is optional, but a quoted count
  must be correct.

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

**Any merge performed by GitHub — `merge`, `squash`, or `rebase` — is committed
by `GitHub <noreply@github.com>`.** GitHub creates the resulting commit
server-side and sets itself as committer; the *author* is preserved, the
*committer* is not. This was verified empirically on this repository:

| Method | author | committer |
|--------|--------|-----------|
| merge commit (`ecdcd3e`) | the PR author | `GitHub <noreply@github.com>` |
| squash (`a61af79`) | the PR author | `GitHub <noreply@github.com>` |

So switching merge method does **not** change commit attribution. Squash merges
are still preferred here — they keep `main` linear and one commit per change —
but choose them for readability, not attribution.

If a workflow genuinely requires the committer identity to be preserved on
`main`, the only way is to merge locally and push the commits directly
(`git merge --ff-only` then `git push`), bypassing GitHub's merge API. That
trades away the PR merge button and any branch protection, which is usually the
worse deal.

None of this is fixable retroactively. The `v0.8.0`, `v0.9.0` and `v0.10.0` tags
all point at merge commits, and those tags are what CI built the published PyPI
artifacts from — rewriting history would orphan the released versions from
`main` for a purely cosmetic gain.

## Cutting a release

**Tagging does not bump the version.** The version lives in three files
(`pyproject.toml`, `o1js_scan/__init__.py`, `package.json`) and a git tag
changes none of them. Bump first, then tag:

```bash
python3 scripts/bump_version.py 0.11.0     # rewrites all three
python3 scripts/bump_version.py --check    # verify (no args does the same)

git commit -am "Release 0.11.0"
git push origin main
```

Then cut the GitHub Release against the **new** commit, with tag `v0.11.0`.
Publishing runs on `release: published` and does PyPI + npm.

The `preflight` job compares the manifests to the tag and fails the whole run
if they disagree, so a forgotten bump can never publish mislabelled artifacts.
That is not hypothetical — `v0.11.0` was first cut without a bump, producing:

```
publish-npm  ->  package.json version 0.10.0 != release tag 0.11.0
PyPI         ->  400: File already exists ('o1js_scan-0.10.0-py3-none-any.whl')
```

Nothing shipped. If you hit that, bump properly, then **delete the tag and the
release** and re-cut it — a tag pointing at un-bumped code is not something to
leave lying around:

```bash
git push origin :refs/tags/v0.11.0     # delete remote tag
git tag -d v0.11.0                     # and the local one
```

Required repository secrets: `PYPI_API_TOKEN`, and `NPM_TOKEN` (an npm
**automation** token — the classic type bypasses 2FA for CI). `workflow_dispatch`
is enabled, so you can exercise the workflow from a branch without a tag; the
tag comparison is skipped in that mode.

## Reporting issues

Please include a minimal o1js or Noir snippet that reproduces the false positive
or missed detection — that's the fastest path to a fix and it usually becomes the
regression test.

For false positives specifically, use the **False-positive report** issue
template — it asks for exactly what a calibration fix needs (the snippet, the
finding, and why the flagged pattern is intended design).

## License

By contributing you agree that your contributions are licensed under Apache-2.0.
