"""Tool logic for the o1js-scan MCP server, with no dependency on the MCP SDK.

``o1js_scan.mcp_server`` is a thin adapter that registers these functions with
the official MCP Python SDK and serves them over stdio. Everything an agent can
observe — the response shape, the fail-closed rules, the wording — lives here,
so it is tested on every Python version the core supports, including the ones
the SDK does not (it requires 3.10+).

The design constraint is that an agent summarizing a scan to a user must not
be able to turn it into "your contract is secure":

* every scan response carries coverage, the scanner version, and the rules
  that ran, as structured fields, not prose;
* a scan that analyzed no files is an **error** (``is_error``), never an
  empty success — the same contract as the CLI's exit 2;
* a scan with no findings says, in the result itself, that this is not a
  soundness or security result.

Read-only: nothing here writes, modifies, or executes a file. Scanned source is
read as text and matched lexically, exactly as the CLI does.
"""

from __future__ import annotations

import dataclasses
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import __version__
from .lexer import analyze_project
from .paths import ScanStats
from .rules import BACKENDS, spec_for, specs_for_backend
from .vuln import meets_threshold

LANG_CHOICES = ("auto", "o1js", "noir")
FAIL_ON_CHOICES = ("critical", "high", "medium", "low", "none")

#: At most this many findings are returned in one response. The counts in
#: ``findings_summary`` always cover every finding; only the list is cut, and
#: the response says so. The CLI has no output cap to reuse — it streams to a
#: terminal — but an agent's context window is finite.
MAX_FINDINGS = 200
#: Longest finding description returned before it is cut with a marker.
MAX_DESCRIPTION_CHARS = 1200

_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")

MISSING_EXTRA_MESSAGE = (
    "The o1js-scan MCP server needs the optional 'mcp' extra, which is not "
    "installed. Install it with:  pip install 'o1js-scan[mcp]'  "
    "(the MCP SDK requires Python 3.10 or newer; the scanner itself does not)."
)


class MCPExtraNotInstalled(ImportError):
    """Raised on importing ``o1js_scan.mcp_server`` without the ``mcp`` extra."""


# ───────────────────────────────────────────────────────────────────
# What the agent reads before calling a tool
# ───────────────────────────────────────────────────────────────────

CLEAN_RESULT_WARNING = (
    "A clean result means no pattern these rules recognize was found. It does "
    "NOT mean the code is sound or secure. This is a lexical triage tool, not "
    "a verifier. Report findings and coverage to the user; never describe a "
    "clean scan as a security guarantee."
)

SERVER_INSTRUCTIONS = (
    "o1js-scan is a local, read-only static analyzer for o1js (Mina zkApp) and "
    "Noir circuit source. It matches a fixed set of code shapes that often mean "
    "a circuit accepts values it should reject, such as a prover-supplied "
    "witness that no constraint binds. " + CLEAN_RESULT_WARNING + " Source code "
    "is read on this machine and never sent anywhere by this server."
)

SCAN_DESCRIPTION = (
    "Scan a file or directory of o1js (TypeScript/JavaScript) or Noir (.nr) "
    "source for known under-constraint patterns, using o1js-scan's rules. "
    "Runs locally and read-only; nothing is executed or uploaded. "
    "Test files are skipped and findings in example code are downgraded to "
    "LOW, as in the CLI; the response counts both. "
    "\n\n" + CLEAN_RESULT_WARNING + "\n\n"
    "Every response includes the scanner version, the rules that ran, and a "
    "`coverage` object (files_matched, files_analyzed, files_skipped with "
    "reasons, and coverage.status). If no o1js or Noir source was analyzed, "
    "the call returns an error: there is no result to report, and it must not "
    "be described as a clean or passing scan. A finding is a lead to review, "
    "not a confirmed vulnerability; use explain_rule for what a rule matches "
    "and what it misses. `gate` applies the fail_on severity threshold the way "
    "the CLI's exit code does; it is a CI gate, not a security verdict."
)

LIST_RULES_DESCRIPTION = (
    "List every rule o1js-scan applies, with its id, language backend, title and "
    "severities. These are the only patterns the scanner recognizes: code shapes "
    "outside them are not checked at all."
)

EXPLAIN_RULE_DESCRIPTION = (
    "Explain one o1js-scan rule: what it matches, why it matters, its severity "
    "spread, and its documented limitations (what it deliberately does not "
    "match). Use it to describe a finding accurately rather than guessing."
)


@dataclasses.dataclass(frozen=True)
class ToolResult:
    """A tool's structured payload and whether it is an MCP tool error."""

    payload: Dict[str, Any]
    is_error: bool = False


# ───────────────────────────────────────────────────────────────────
# scan
# ───────────────────────────────────────────────────────────────────

def _lang_noun(lang: str) -> str:
    return {"noir": "Noir", "o1js": "o1js"}.get(lang, "o1js or Noir")


def _not_source_key(lang: str) -> str:
    return {"o1js": "not_o1js_source", "noir": "not_noir_source"}.get(
        lang, "not_o1js_or_noir_source")


def _gaps(stats: ScanStats) -> int:
    """Files that might have held analyzable source but were never examined.

    A file the content check read and rejected was examined, so it is not a gap.
    """
    return stats.skipped_test_files + stats.unreadable_files + stats.outside_root_files


def _backends_for(lang: str) -> Tuple[str, ...]:
    return BACKENDS if lang == "auto" else (lang,)


def _coverage(stats: ScanStats, lang: str) -> Dict[str, Any]:
    skipped = {
        "test_code": stats.skipped_test_files,
        _not_source_key(lang): stats.not_source_files,
        "unreadable": stats.unreadable_files,
        "symlink_outside_root": stats.outside_root_files,
    }
    # Files that might have held analyzable source but were not examined. A
    # file the content check rejected was examined and is not a coverage gap.
    gaps = _gaps(stats)
    if stats.analyzed_files == 0:
        status = "none"
    elif gaps:
        status = "partial"
    else:
        status = "all_candidate_files_examined"

    notes: List[str] = []
    if stats.skipped_test_files:
        notes.append(
            f"{stats.skipped_test_files} file(s) under test paths were skipped, as "
            f"the CLI does by default; a contract stored under a test path was not "
            f"analyzed."
        )
    if stats.unreadable_files:
        notes.append(f"{stats.unreadable_files} file(s) could not be read.")
    if stats.outside_root_files:
        notes.append(
            f"{stats.outside_root_files} file(s) were symlinks resolving outside the "
            f"requested path and were refused without being read."
        )
    if stats.not_source_files:
        notes.append(
            f"{stats.not_source_files} matched file(s) were read and found not to "
            f"be {_lang_noun(lang)} source, so no rule applied to them."
        )
    if stats.downgraded_example_findings:
        notes.append(
            f"{stats.downgraded_example_findings} finding(s) in example code were "
            f"downgraded to LOW; each carries `downgraded_from`."
        )
    if status == "all_candidate_files_examined":
        notes.append(
            "Every matched file was either analyzed or determined not to be "
            "source. This describes which files were read, not how much of the "
            "code's behavior the rules can see."
        )
    return {
        "status": status,
        "files_matched": stats.matched_files,
        "files_analyzed": stats.analyzed_files,
        "files_analyzed_by_language": {
            "o1js": stats.analyzed_o1js_files,
            "noir": stats.analyzed_noir_files,
        },
        "files_skipped": {"total": sum(skipped.values()), **skipped},
        "files_not_examined": gaps,
        "notes": notes,
    }


def _rules_run(stats: Optional[ScanStats], lang: str) -> Dict[str, Any]:
    """The rules applied: a backend's rules run on every file its lexer saw."""
    if stats is None:
        backends: Tuple[str, ...] = ()
    else:
        seen = {"o1js": stats.analyzed_o1js_files, "noir": stats.analyzed_noir_files}
        backends = tuple(b for b in _backends_for(lang) if seen[b])
    ids = [s.rule_id for b in backends for s in specs_for_backend(b)]
    return {"backends_run": list(backends), "rule_count": len(ids), "rule_ids": ids}


def _cut(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f" … [truncated: {len(text) - limit} more characters]"


def _finding(fp: str, v: Any, root: Path) -> Dict[str, Any]:
    p = Path(fp)
    try:
        shown = p.relative_to(root).as_posix() if root.is_dir() else p.name
    except ValueError:
        shown = p.as_posix()
    item = {
        "file": shown,
        "line": (v.location or [0])[0],
        "rule_id": v.rule_id,
        "severity": v.severity.value.lower(),
        "function": v.function,
        "title": v.title,
        "description": _cut(v.description or "", MAX_DESCRIPTION_CHARS),
    }
    down = (v.evidence or {}).get("downgraded_from")
    if down:
        item["downgraded_from"] = str(down).lower()
    return item


def _sort_key(f: Dict[str, Any]) -> Tuple[int, str, int]:
    sev = f["severity"]
    rank = _SEVERITY_ORDER.index(sev) if sev in _SEVERITY_ORDER else len(_SEVERITY_ORDER)
    return (rank, f["file"], f["line"])


def _response(
    *,
    path: str,
    resolved: Optional[Path],
    lang: str,
    fail_on: str,
    stats: Optional[ScanStats],
    findings: List[Dict[str, Any]],
    error: Optional[Dict[str, str]],
) -> ToolResult:
    """One shape for every outcome, so an error validates against the same schema."""
    # Invariant, enforced where every response is built rather than only in
    # scan(): a result that analyzed nothing is never a success. If a future
    # code path forgets the check, it still cannot emit "ok, 0 findings".
    if error is None and (stats is None or stats.analyzed_files == 0):
        error = {
            "code": "nothing_analyzed",
            "message": f"No {_lang_noun(lang)} sources were analyzed at {path}.",
        }
    total = len(findings)
    returned = sorted(findings, key=_sort_key)[:MAX_FINDINGS]
    truncated = total > len(returned)
    by_sev = Counter(f["severity"] for f in findings)
    coverage = _coverage(stats if stats is not None else ScanStats(), lang)
    rules = _rules_run(stats, lang)

    if error is not None:
        outcome = "not_scanned"
        gate = {"fail_on": fail_on, "result": "not_evaluated"}
        interpretation = (
            f"ERROR: {error['message']} There is no scan result to report. Do NOT "
            f"describe this as a clean, passing, or secure scan."
        )
    else:
        failed = any(meets_threshold(f["severity"], fail_on) for f in findings)
        gate = {"fail_on": fail_on, "result": "failed" if failed else "passed"}
        analyzed = coverage["files_analyzed"]
        if total:
            outcome = "patterns_matched"
            files_hit = len({f["file"] for f in findings})
            interpretation = (
                f"{total} finding(s) from lexical pattern matching in {files_hit} of "
                f"{analyzed} analyzed file(s). Each finding is a lead to review, not a "
                f"confirmed vulnerability. Files without findings are not thereby "
                f"shown to be sound."
            )
        else:
            outcome = "no_known_patterns_matched"
            interpretation = (
                f"No pattern these {rules['rule_count']} rules recognize matched in "
                f"the {analyzed} analyzed file(s). This does NOT mean the code is "
                f"sound or secure: o1js-scan is a lexical triage tool, not a "
                f"verifier, and many bug classes are outside what its rules can "
                f"see. Report this as 'no known patterns matched', with the "
                f"coverage below, never as 'secure' or 'no vulnerabilities'."
            )
        if coverage["status"] == "partial":
            interpretation += (
                f" Coverage is PARTIAL: {coverage['files_not_examined']} candidate "
                f"file(s) were not examined; see coverage.notes."
            )

    payload: Dict[str, Any] = {
        "status": "error" if error is not None else "ok",
        "outcome": outcome,
        "interpretation": interpretation,
        "error": error,
        "scanner": {
            "name": "o1js-scan",
            "version": __version__,
            "method": "lexical pattern matching on source text; no type checking, "
                      "no constraint solving, no execution of scanned code",
        },
        "request": {
            "path": path,
            "resolved_path": str(resolved) if resolved is not None else None,
            "lang": lang,
            "fail_on": fail_on,
        },
        "coverage": coverage,
        "rules": rules,
        "gate": gate,
        "findings_summary": {
            "total": total,
            "returned": len(returned),
            "by_severity": {s: by_sev[s] for s in _SEVERITY_ORDER if by_sev[s]},
            "files_with_findings": len({f["file"] for f in findings}),
        },
        "truncated": truncated,
        "truncation_note": (
            f"Only the first {len(returned)} of {total} findings are listed, highest "
            f"severity first. The counts in findings_summary cover all {total}. "
            f"Scan a narrower path to see the rest."
            if truncated else None
        ),
        "findings": returned,
    }
    return ToolResult(payload=payload, is_error=error is not None)


def scan(path: str, lang: str = "auto", fail_on: str = "high") -> ToolResult:
    """Run the existing analyzer on ``path`` and wrap the result for an agent.

    Fails closed: a missing path, an invalid argument, or a scan that analyzed
    no files returns an error result rather than an empty success.
    """
    lang = (lang or "").lower()
    fail_on = (fail_on or "").lower()
    args = {"path": path, "lang": lang, "fail_on": fail_on, "stats": None,
            "findings": [], "resolved": None}

    if lang not in LANG_CHOICES:
        return _response(**args, error={
            "code": "invalid_argument",
            "message": f"lang must be one of {', '.join(LANG_CHOICES)}; got {lang!r}.",
        })
    if fail_on not in FAIL_ON_CHOICES:
        return _response(**args, error={
            "code": "invalid_argument",
            "message": f"fail_on must be one of {', '.join(FAIL_ON_CHOICES)}; got {fail_on!r}.",
        })
    if not isinstance(path, str) or not path.strip():
        return _response(**args, error={
            "code": "invalid_argument", "message": "path must be a non-empty string.",
        })

    requested = Path(path).expanduser()
    if not requested.exists():
        return _response(**args, error={
            "code": "path_not_found",
            "message": f"Path not found: {path}. Nothing was scanned.",
        })
    resolved = requested.resolve()
    args["resolved"] = resolved

    stats = ScanStats()
    args["stats"] = stats
    try:
        raw = analyze_project(
            str(resolved), lang=lang, include_tests=False, include_examples=False,
            stats=stats, confine_to_root=True,
        )
    except Exception as exc:  # noqa: BLE001 — reported to the agent, never swallowed
        return _response(**args, error={
            "code": "scan_failed",
            "message": f"The scan failed before completing: {type(exc).__name__}: {exc}",
        })

    if stats.analyzed_files == 0:
        reason = (
            f"{stats.matched_files} file(s) matched the scan globs but none was "
            f"analyzed (see coverage.files_skipped)"
            if stats.matched_files else "no files matched the scan globs"
        )
        return _response(**args, error={
            "code": "nothing_analyzed",
            "message": (
                f"No {_lang_noun(lang)} sources were analyzed at {path}: {reason}."
            ),
        })

    args["findings"] = [_finding(fp, v, resolved) for fp, v in raw]
    return _response(**args, error=None)


# ───────────────────────────────────────────────────────────────────
# list_rules / explain_rule
# ───────────────────────────────────────────────────────────────────

def list_rules() -> ToolResult:
    rules = [
        {
            "rule_id": s.rule_id,
            "backend": s.backend,
            "title": s.title,
            "severities": list(s.severities),
        }
        for b in BACKENDS for s in specs_for_backend(b)
    ]
    return ToolResult(payload={
        "scanner": {"name": "o1js-scan", "version": __version__},
        "rule_count": len(rules),
        "rules": rules,
        "interpretation": (
            "These are the only patterns o1js-scan recognizes. Code shapes outside "
            "them are not checked, so the absence of a finding is not evidence of "
            "soundness."
        ),
    })


def explain_rule(rule_id: str) -> ToolResult:
    spec = spec_for(rule_id) if isinstance(rule_id, str) else None
    if spec is None:
        return ToolResult(is_error=True, payload={
            "error": {
                "code": "unknown_rule",
                "message": f"No rule with id {rule_id!r}. Call list_rules for the valid ids.",
            },
        })
    return ToolResult(payload={
        "rule_id": spec.rule_id,
        "backend": spec.backend,
        "title": spec.title,
        "severities": list(spec.severities),
        "default_severity": spec.default_severity,
        "description": spec.description,
        "limitations": spec.limitations,
        "origin": spec.origin,
        "scanner": {"name": "o1js-scan", "version": __version__},
    })
