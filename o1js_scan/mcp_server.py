"""Local stdio MCP server for o1js-scan.

    pip install 'o1js-scan[mcp]'
    o1js-scan-mcp                 # or: python -m o1js_scan.mcp_server

Serves three read-only tools over stdio, built on the official MCP Python SDK:
``scan``, ``list_rules`` and ``explain_rule``. There is no network transport:
the server is a subprocess of the editor or agent that launched it, and the
source it scans never leaves the machine.

This module is only the adapter between the SDK and ``o1js_scan.mcp_tools``,
which holds the tool logic and response shape without importing the SDK. The
core package keeps zero runtime dependencies; the SDK arrives only with the
``mcp`` extra, and importing this module without it raises
:class:`~o1js_scan.mcp_tools.MCPExtraNotInstalled` naming the extra.
"""

from __future__ import annotations

import json
import sys
from typing import Dict, List, Literal, Optional

from . import __version__
from . import mcp_tools as tools
from .mcp_tools import MISSING_EXTRA_MESSAGE, MCPExtraNotInstalled

try:
    from mcp.server import MCPServer
    from mcp.types import CallToolResult, TextContent, ToolAnnotations
    from pydantic import BaseModel, Field
except ImportError as exc:  # the extra is missing, or Python is older than the SDK supports
    raise MCPExtraNotInstalled(MISSING_EXTRA_MESSAGE) from exc

# After the SDK import, so on Python 3.8 the missing-extra message wins over a
# bare "cannot import name 'Annotated'".
from typing import Annotated  # noqa: E402

# Every tool here only reads files. openWorldHint=False: the tools touch the
# local filesystem only, never an external system.
_READ_ONLY = ToolAnnotations(
    readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False,
)


# ───────────────────────────────────────────────────────────────────
# Output schema for `scan`. It mirrors mcp_tools._response, which builds one
# shape for success and error alike, so an error result conforms to the
# published schema too (the spec requires structured results to conform).
# tests/test_mcp_server.py validates every outcome against it.
# ───────────────────────────────────────────────────────────────────

class ScanError(BaseModel):
    code: Literal["invalid_argument", "path_not_found", "nothing_analyzed", "scan_failed"]
    message: str


class Scanner(BaseModel):
    name: str
    version: str
    method: str


class ScanRequest(BaseModel):
    path: str
    resolved_path: Optional[str]
    lang: str
    fail_on: str


class FilesSkipped(BaseModel):
    model_config = {"extra": "allow"}  # the not-source key is named for the language
    total: int
    test_code: int
    unreadable: int
    symlink_outside_root: int


class Coverage(BaseModel):
    status: Literal["none", "partial", "all_candidate_files_examined"] = Field(
        description="'none' only on error. 'partial' means files that might hold "
                    "source were not examined. Neither value is a soundness claim."
    )
    files_matched: int
    files_analyzed: int
    files_analyzed_by_language: Dict[str, int]
    files_skipped: FilesSkipped
    files_not_examined: int
    notes: List[str]


class RulesRun(BaseModel):
    backends_run: List[str]
    rule_count: int
    rule_ids: List[str]


class Gate(BaseModel):
    fail_on: str
    result: Literal["passed", "failed", "not_evaluated"] = Field(
        description="The CLI's exit-code gate at the fail_on threshold. A CI gate, "
                    "not a security verdict."
    )


class FindingsSummary(BaseModel):
    total: int
    returned: int
    by_severity: Dict[str, int]
    files_with_findings: int


class Finding(BaseModel):
    file: str
    line: int
    rule_id: str
    severity: str
    function: Optional[str]
    title: str
    description: str
    downgraded_from: Optional[str] = None


class ScanResponse(BaseModel):
    status: Literal["ok", "error"]
    outcome: Literal["patterns_matched", "no_known_patterns_matched", "not_scanned"]
    interpretation: str = Field(
        description="How to report this result. Relay it; do not upgrade it."
    )
    error: Optional[ScanError]
    scanner: Scanner
    request: ScanRequest
    coverage: Coverage
    rules: RulesRun
    gate: Gate
    findings_summary: FindingsSummary
    truncated: bool
    truncation_note: Optional[str]
    findings: List[Finding]


def _result(outcome: tools.ToolResult) -> CallToolResult:
    """Structured content plus the same JSON as text, as the spec recommends."""
    return CallToolResult(
        content=[TextContent(type="text", text=json.dumps(outcome.payload, indent=2))],
        structured_content=outcome.payload,
        is_error=outcome.is_error,
    )


def build_server() -> MCPServer:
    server = MCPServer(
        name="o1js-scan",
        version=__version__,
        instructions=tools.SERVER_INSTRUCTIONS,
    )

    @server.tool(name="scan", description=tools.SCAN_DESCRIPTION, annotations=_READ_ONLY)
    def scan(
        path: Annotated[str, Field(
            description="File or directory to scan. A relative path resolves against "
                        "the server's working directory; the response reports the "
                        "resolved path.")],
        lang: Annotated[Literal["auto", "o1js", "noir"], Field(
            description="Which sources to analyze; auto = both.")] = "auto",
        fail_on: Annotated[Literal["critical", "high", "medium", "low", "none"], Field(
            description="Severity threshold for the `gate` field.")] = "high",
    ) -> Annotated[CallToolResult, ScanResponse]:
        return _result(tools.scan(path, lang=lang, fail_on=fail_on))

    @server.tool(name="list_rules", description=tools.LIST_RULES_DESCRIPTION,
                 annotations=_READ_ONLY)
    def list_rules() -> CallToolResult:
        return _result(tools.list_rules())

    @server.tool(name="explain_rule", description=tools.EXPLAIN_RULE_DESCRIPTION,
                 annotations=_READ_ONLY)
    def explain_rule(
        rule_id: Annotated[str, Field(
            description="A rule id from list_rules, e.g. O1JS_UNCONSTRAINED_WITNESS.")],
    ) -> CallToolResult:
        return _result(tools.explain_rule(rule_id))

    return server


def main() -> int:
    """Serve over stdio until the client closes the connection."""
    build_server().run("stdio")
    return 0


if __name__ == "__main__":
    sys.exit(main())

