"""Path-based finding policy, shared by the o1js and Noir backends.

Two classifications, applied uniformly to both languages so a user does not
have to remember which backend honours which convention:

**Test code — suppressed by default.** Tests deliberately construct invalid
values and bad transactions to prove the asserts reject them, so a finding
there is the point of the test rather than a circuit bug. Both ecosystems keep
contracts under test paths (`Foo.test.ts`, `__tests__/`, `*_test.nr`,
`tests/`), so without this every project reports its own test suite.

**Example code — downgraded, not dropped.** Illustrative code is deliberately
simplified and flagging a framework's own examples as vulnerabilities is noise.
But example code gets copied into production far more often than test code
does, so it is lowered to LOW with a note rather than hidden: still visible on
a full report, no longer failing anyone's build.

Detection is **path and filename only** — no attempt to parse `describe(` /
`it(` blocks. That keeps it predictable and language-agnostic; the cost is that
a production circuit stored under `tests/` is skipped, which is why the CLI
reports how many files were skipped.
"""

from __future__ import annotations

import dataclasses
import re
from typing import List, Optional, Tuple

from .vuln import Severity, Vulnerability

# `Foo.test.ts`, `Foo.spec.js`, … (o1js/TS-JS) and `foo_test.nr` / `test_foo.nr`
# (Noir). Kept as one list so both backends stay in step.
_TEST_FILE_RE = re.compile(
    r"(?:"
    r"\.(?:test|spec)\.(?:ts|tsx|js|jsx|mjs|cjs)$"
    r"|(?:^|/)test_[^/]*\.nr$"
    r"|(?:^|/)[^/]*_test\.nr$"
    r")"
)
_TEST_DIR_SEGMENTS = frozenset({"test", "tests", "__tests__", "spec", "__mocks__"})

_EXAMPLE_FILE_RE = re.compile(r"\.eg\.(?:ts|tsx|js|jsx|mjs|cjs|nr)$")
_EXAMPLE_DIR_SEGMENTS = frozenset({"example", "examples"})

_EXAMPLE_NOTE = (
    " NOTE: this file looks like example/illustrative code (an `examples/` "
    "directory or an `.eg.` filename), so the finding has been downgraded to "
    "LOW and will not fail a build. Example code is simplified on purpose — but "
    "it is also copied into production more often than test code is, so it is "
    "reported rather than hidden. Re-run with `--include-examples` for the "
    "original severity."
)


def _segments(filepath: str) -> List[str]:
    return str(filepath).replace("\\", "/").split("/")


def is_test_path(filepath: str) -> bool:
    """True for a test filename or any path under a test directory."""
    p = str(filepath).replace("\\", "/")
    if _TEST_FILE_RE.search(p):
        return True
    return any(seg in _TEST_DIR_SEGMENTS for seg in _segments(p)[:-1])


def is_example_path(filepath: str) -> bool:
    """True for an ``.eg.`` filename or any path under an example directory."""
    p = str(filepath).replace("\\", "/")
    if _EXAMPLE_FILE_RE.search(p):
        return True
    return any(seg in _EXAMPLE_DIR_SEGMENTS for seg in _segments(p)[:-1])


def downgrade_example(vuln: Vulnerability) -> Vulnerability:
    """Return a copy of ``vuln`` lowered to LOW with an explanatory note."""
    if vuln.severity == Severity.LOW:
        return vuln
    return dataclasses.replace(
        vuln,
        severity=Severity.LOW,
        description=(vuln.description or "") + _EXAMPLE_NOTE,
        evidence={**(vuln.evidence or {}), "downgraded_from": vuln.severity.value,
                  "downgrade_reason": "example_code"},
    )


def apply_example_policy(
    filepath: str, vulns: List[Vulnerability], include_examples: bool = False,
) -> Tuple[List[Vulnerability], int]:
    """Downgrade findings from example code. Returns ``(vulns, n_downgraded)``."""
    if include_examples or not vulns or not is_example_path(filepath):
        return vulns, 0
    out = [downgrade_example(v) for v in vulns]
    return out, sum(1 for a, b in zip(vulns, out) if a.severity != b.severity)


@dataclasses.dataclass
class ScanStats:
    """Counts of what path policy suppressed or downgraded during a scan."""

    skipped_test_files: int = 0
    downgraded_example_findings: int = 0

    def note(self) -> Optional[str]:
        """A one-line human summary, or ``None`` when nothing was affected."""
        parts = []
        if self.skipped_test_files:
            parts.append(f"{self.skipped_test_files} file(s) skipped as test code")
        if self.downgraded_example_findings:
            parts.append(
                f"{self.downgraded_example_findings} finding(s) downgraded as examples"
            )
        if not parts:
            return None
        return ", ".join(parts) + " (--include-tests, --include-examples to override)"
