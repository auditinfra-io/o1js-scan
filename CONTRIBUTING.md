# Contributing to o1js-scan

Thanks for helping make o1js zkApps safer. Contributions of new rule families,
false-positive guards, and real-world calibration archetypes are all welcome.

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
  o1js is worse than no rule. When in doubt, prefer a false negative (miss) over
  a false positive — this tool's output is meant to be trusted enough to triage.
- **Lexical, not a full parser.** The analyzer is deliberately regex/brace-based
  so it stays dependency-free and instant. New rules should fit that model.
- **Findings are leads, not proofs.** Descriptions should tell a reviewer what to
  check and why, not assert that a bug definitely exists.

## Adding a rule

1. Add the detection method to `O1jsLexer` in `o1js_scan/lexer.py`.
2. Give it a stable `rule_id` and a clear `title` + `description`.
3. Add tests to `tests/test_lexer.py` covering the positive case and the FP guards.
4. Document the rule in the table in `README.md`.

## Reporting issues

Please include a minimal o1js snippet that reproduces the false positive or
missed detection — that's the fastest path to a fix and it usually becomes the
regression test.

## License

By contributing you agree that your contributions are licensed under Apache-2.0.
