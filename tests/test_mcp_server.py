"""The MCP server over a real stdio connection, with the official SDK as client.

Skipped unless the ``mcp`` extra is installed (``pip install -e '.[dev,mcp]'``);
CI runs it in the ``mcp-server`` job. The tool logic itself is covered on every
Python by ``tests/test_mcp_tools.py`` — this file proves the wire: that the
server starts as a subprocess, advertises read-only tools with the required
description, and that an error result reaches the client as ``isError`` with
structured content that conforms to the published output schema.
"""

from __future__ import annotations

import asyncio
import shutil
import sys
from pathlib import Path

import pytest

mcp = pytest.importorskip("mcp", reason="the 'mcp' extra is not installed")
jsonschema = pytest.importorskip("jsonschema")

from mcp import Client, StdioServerParameters  # noqa: E402

from o1js_scan import __version__  # noqa: E402
from o1js_scan.mcp_tools import CLEAN_RESULT_WARNING  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
VULNERABLE = REPO_ROOT / "examples" / "vulnerable_vault.ts"
SAFE_NOIR = REPO_ROOT / "examples" / "noir_constrained.nr"


def _server() -> StdioServerParameters:
    # The module form, so the test does not depend on where pip put the script.
    return StdioServerParameters(command=sys.executable, args=["-m", "o1js_scan.mcp_server"])


def _session(fn):
    async def run():
        async with Client(_server()) as client:
            return await fn(client)
    return asyncio.run(run())


def _call(name: str, args: dict):
    async def go(client):
        tools = {t.name: t for t in (await client.list_tools()).tools}
        result = await client.call_tool(name, args)
        return tools, result
    return _session(go)


def _validate(tools, result) -> None:
    schema = tools["scan"].output_schema
    assert schema, "scan publishes no outputSchema"
    jsonschema.validate(result.structured_content, schema)


def test_server_identifies_itself_and_lists_three_read_only_tools():
    async def go(client):
        return client.server_info if hasattr(client, "server_info") else None, (
            await client.list_tools()
        ).tools
    info, tools = _session(go)
    if info is not None:
        assert info.name == "o1js-scan" and info.version == __version__
    assert sorted(t.name for t in tools) == ["explain_rule", "list_rules", "scan"]
    for t in tools:
        assert t.annotations.read_only_hint is True, t.name
        assert t.annotations.destructive_hint is False, t.name
        assert t.annotations.open_world_hint is False, t.name


def test_scan_description_carries_the_clean_result_warning_verbatim():
    async def go(client):
        return {t.name: t for t in (await client.list_tools()).tools}
    tools = _session(go)
    assert CLEAN_RESULT_WARNING in tools["scan"].description


def test_empty_directory_reaches_the_client_as_an_error(tmp_path):
    """The important one, end to end: isError, and no field that reads 'clean'."""
    tools, r = _call("scan", {"path": str(tmp_path)})
    assert r.is_error is True
    sc = r.structured_content
    assert sc["status"] == "error"
    assert sc["outcome"] == "not_scanned"
    assert sc["coverage"]["status"] == "none"
    assert sc["coverage"]["files_analyzed"] == 0
    assert sc["error"]["message"].startswith(
        f"No o1js or Noir sources were analyzed at {tmp_path}")
    # The text block an agent may read instead carries the same verdict.
    assert '"status": "error"' in r.content[0].text
    assert "Do NOT describe this as a clean" in r.content[0].text
    _validate(tools, r)


def test_mutation_directory_without_sources_is_an_error_over_the_wire(tmp_path):
    (tmp_path / "server.ts").write_text("export const port = 8080;\n", encoding="utf-8")
    tools, r = _call("scan", {"path": str(tmp_path)})
    assert r.is_error is True
    assert r.structured_content["coverage"]["files_skipped"]["not_o1js_or_noir_source"] == 1
    _validate(tools, r)


def test_nonexistent_path_is_an_error(tmp_path):
    tools, r = _call("scan", {"path": str(tmp_path / "missing")})
    assert r.is_error is True
    assert r.structured_content["error"]["code"] == "path_not_found"
    _validate(tools, r)


def test_vulnerable_example_returns_findings_and_coverage(tmp_path):
    target = tmp_path / VULNERABLE.name
    shutil.copy(VULNERABLE, target)
    tools, r = _call("scan", {"path": str(target), "fail_on": "medium"})
    assert r.is_error is False
    sc = r.structured_content
    assert sc["outcome"] == "patterns_matched"
    assert sc["findings"] and sc["coverage"]["files_analyzed"] == 1
    assert sc["scanner"]["version"] == __version__
    assert sc["rules"]["rule_ids"]
    assert sc["gate"] == {"fail_on": "medium", "result": "failed"}
    _validate(tools, r)


def test_safe_example_is_success_with_coverage(tmp_path):
    target = tmp_path / SAFE_NOIR.name
    shutil.copy(SAFE_NOIR, target)
    tools, r = _call("scan", {"path": str(target)})
    assert r.is_error is False
    sc = r.structured_content
    assert sc["outcome"] == "no_known_patterns_matched"
    assert sc["coverage"]["files_analyzed"] == 1
    assert sc["rules"]["backends_run"] == ["noir"]
    assert "does NOT mean the code is sound or secure" in sc["interpretation"]
    _validate(tools, r)


def test_schema_rejected_arguments_are_errors(tmp_path):
    _tools, r = _call("scan", {"path": str(tmp_path), "lang": "rust"})
    assert r.is_error is True


def test_list_and_explain_rules():
    _tools, r = _call("list_rules", {})
    assert r.is_error is False and r.structured_content["rule_count"] > 0
    first = r.structured_content["rules"][0]["rule_id"]
    _tools, r = _call("explain_rule", {"rule_id": first})
    assert r.is_error is False and r.structured_content["rule_id"] == first
    _tools, r = _call("explain_rule", {"rule_id": "NOPE"})
    assert r.is_error is True
