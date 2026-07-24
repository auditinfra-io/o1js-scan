"""o1js-scan — a static soundness analyzer for o1js / Mina zkApps.

Public API:
    analyze_file(filepath, source) -> list[Vulnerability]
    analyze_project(root)          -> list[(filepath, Vulnerability)]
    is_o1js_source(content, path)  -> bool
    O1jsLexer                      -> the analyzer class
    Severity, Vulnerability        -> finding types
"""

from __future__ import annotations

from .lexer import (
    O1JS_ORIGIN_TIER,
    O1jsLexer,
    analyze_file,
    analyze_project,
    is_o1js_source,
)
from .vuln import Severity, Vulnerability

__version__ = "0.5.0"

__all__ = [
    "O1jsLexer",
    "analyze_file",
    "analyze_project",
    "is_o1js_source",
    "Severity",
    "Vulnerability",
    "O1JS_ORIGIN_TIER",
    "__version__",
]
