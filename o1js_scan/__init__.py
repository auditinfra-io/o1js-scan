"""o1js-scan — a static soundness analyzer for o1js / Mina zkApps and Noir.

Public API:
    analyze_file(filepath, source) -> list[Vulnerability]
    analyze_project(root)          -> list[(filepath, Vulnerability)]
    is_o1js_source(content, path)  -> bool
    is_noir_source(content, path)  -> bool
    O1jsLexer, NoirLexer           -> the analyzer classes
    Severity, Vulnerability        -> finding types

`analyze_file` / `analyze_project` dispatch by extension: `.nr` files are
analyzed as Noir circuits, `.ts` / `.js` / `.mjs` as o1js zkApps.
"""

from __future__ import annotations

from .lexer import (
    O1JS_ORIGIN_TIER,
    O1jsLexer,
    analyze_file,
    analyze_project,
    is_o1js_source,
)
from .noir import NOIR_ORIGIN_TIER, NoirLexer, analyze_noir_file, is_noir_source
from .paths import ScanStats, is_example_path, is_test_path
from .vuln import Severity, Vulnerability

__version__ = "0.12.0"

__all__ = [
    "O1jsLexer",
    "NoirLexer",
    "analyze_file",
    "analyze_project",
    "analyze_noir_file",
    "is_o1js_source",
    "is_noir_source",
    "Severity",
    "Vulnerability",
    "O1JS_ORIGIN_TIER",
    "NOIR_ORIGIN_TIER",
    "ScanStats",
    "is_test_path",
    "is_example_path",
    "__version__",
]
