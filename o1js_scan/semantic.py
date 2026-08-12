"""Small, dependency-free semantic facts for TypeScript-shaped o1js code.

This is deliberately not an o1js rule engine.  It extracts reusable facts
(aliases, calls, effects and constraints) and computes inter-procedural
summaries to a fixed point.  Rules consume the resulting summaries without
having to grow their own regex-based dataflow implementation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Set, Tuple

_IDENT = re.compile(r"\b[A-Za-z_$][\w$]*\b")
_ASSIGN = re.compile(
    r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)"
    r"(?:\s*:\s*[^=;\n]+)?\s*=\s*([^;]+)"
)
_CALL = re.compile(r"\bthis\s*\.\s*(\w+)\s*\(")
_ASSERT = re.compile(
    r"(?<![\w.()])([\w.()]{1,240})\s*\.\s*(assertEquals|assertLessThan|assertLessThanOrEqual|"
    r"assertGreaterThan|assertGreaterThanOrEqual|assertNotEquals|requireEquals)\s*\("
)


def _paren(src: str, opening: int) -> Tuple[str, int]:
    depth = 1
    i = opening + 1
    while i < len(src) and depth:
        if src[i] == "(":
            depth += 1
        elif src[i] == ")":
            depth -= 1
        i += 1
    return src[opening + 1:i - 1], i


def _split_args(src: str) -> List[str]:
    out, start, depth = [], 0, 0
    for i, char in enumerate(src):
        if char in "([{<":
            depth += 1
        elif char in ")]}>" and depth:
            depth -= 1
        elif char == "," and depth == 0:
            out.append(src[start:i].strip())
            start = i + 1
    out.append(src[start:].strip())
    return out if any(out) else []


@dataclass(frozen=True)
class EffectFact:
    """A state-changing effect reachable from an entry method."""

    kind: str
    offset: int
    expression: str


@dataclass(frozen=True)
class ProvenanceStep:
    """One analyzer-observed source location in a witness flow."""

    kind: str
    label: str
    method: str
    line: int


@dataclass(frozen=True)
class WitnessExplanation:
    """A conservative source-to-effect explanation for :meth:`witness`."""

    source: str
    flow: Tuple[ProvenanceStep, ...]
    sink: str
    binding: str

    def to_dict(self) -> Dict:
        return {
            "source": self.source,
            "flow": [
                {"kind": s.kind, "label": s.label, "method": s.method, "line": s.line}
                for s in self.flow
            ],
            "sink": self.sink,
            "binding": self.binding,
        }


@dataclass
class _Summary:
    effects: Dict[int, EffectFact]
    constraints: Dict[int, str]
    paths: Dict[int, Optional[Tuple[ProvenanceStep, ...]]]


class SemanticFacts:
    """Computed alias/dataflow facts for one contract.

    ``methods`` only needs objects exposing ``name``, ``params`` and ``body``;
    this keeps the layer independent from the scanner's parser and findings.
    """

    def __init__(self, methods: Iterable[object], state_fields: Iterable[str]):
        method_list = list(methods)
        grouped: Dict[Tuple[int, str], List[object]] = {}
        for method in method_list:
            grouped.setdefault((getattr(method, "semantic_scope", 0), method.name), []).append(method)
        # An overloaded/duplicate name is not an exact call edge.  Excluding it
        # prevents both incorrect facts and fabricated explanations.
        self.methods = {key: values[0] for key, values in grouped.items() if len(values) == 1}
        self.state_fields = set(state_fields)
        self._summaries: Dict[Tuple[int, str], _Summary] = {
            name: _Summary({}, {}, {}) for name in self.methods
        }
        self._compute()

    def witness(self, method: object, parameter_index: int) -> Tuple[Optional[EffectFact], str]:
        """Return the first reachable effect and constraint level for a parameter."""
        key = (getattr(method, "semantic_scope", 0), method.name)
        summary = self._summaries.get(key, _Summary({}, {}, {}))
        return summary.effects.get(parameter_index), summary.constraints.get(parameter_index, "none")

    def explain_witness(
        self, method: object, parameter_index: int,
    ) -> Optional[WitnessExplanation]:
        """Explain a proven witness flow, or return ``None`` if it is ambiguous."""
        key = (getattr(method, "semantic_scope", 0), method.name)
        summary = self._summaries.get(key)
        if summary is None or parameter_index >= len(method.params):
            return None
        effect = summary.effects.get(parameter_index)
        path = summary.paths.get(parameter_index)
        if effect is None or path is None:
            return None
        param = method.params[parameter_index]
        source_line = getattr(method, "start_line", 1)
        source = f"{method.name}({param}) @method parameter"
        source_step = ProvenanceStep("source", source, method.name, source_line)
        return WitnessExplanation(
            source, (source_step,) + path, path[-1].label,
            summary.constraints.get(parameter_index, "none"),
        )

    @staticmethod
    def _line(method: object, offset: int) -> int:
        return getattr(method, "start_line", 1) + method.body.count("\n", 0, offset)

    def _alias_paths(self, method: object) -> Dict[str, Dict[int, Optional[Tuple[ProvenanceStep, ...]]]]:
        paths = {p: {i: ()} for i, p in enumerate(method.params)}
        assignments = list(_ASSIGN.finditer(method.body))
        for _ in range(len(assignments) + 1):
            changed = False
            for match in assignments:
                rhs = match.group(2).strip()
                if not re.fullmatch(r"[A-Za-z_$][\w$]*", rhs):
                    continue
                for index, prefix in paths.get(rhs, {}).items():
                    step = ProvenanceStep(
                        "alias", f"{match.group(1)} = {rhs}", method.name,
                        self._line(method, match.start()),
                    )
                    candidate = None if prefix is None else prefix + (step,)
                    current = paths.setdefault(match.group(1), {}).get(index, "missing")
                    if current == "missing":
                        paths[match.group(1)][index] = candidate
                        changed = True
                    elif current != candidate and current is not None:
                        paths[match.group(1)][index] = None
                        changed = True
            if not changed:
                break
        return paths

    @staticmethod
    def _deps(body: str, params: List[str]) -> Dict[str, Set[int]]:
        deps = {p: {i} for i, p in enumerate(params)}
        # Source order plus a fixed point handles arbitrarily long and forward
        # alias chains without pretending property names are variables.
        assignments = list(_ASSIGN.finditer(body))
        changed = True
        while changed:
            changed = False
            for match in assignments:
                rhs = match.group(2).strip()
                # Alias facts are identity-preserving assignments only.  An
                # arithmetic/method expression is a newly derived circuit
                # value and must not be conflated with its inputs.
                if not re.fullmatch(r"[A-Za-z_$][\w$]*", rhs):
                    continue
                found: Set[int] = set()
                for ident in _IDENT.findall(rhs):
                    found |= deps.get(ident, set())
                if found - deps.get(match.group(1), set()):
                    deps.setdefault(match.group(1), set()).update(found)
                    changed = True
        return deps

    def _state_locals(self, body: str) -> Set[str]:
        result = set()
        for match in _ASSIGN.finditer(body):
            expr = match.group(2)
            if any(re.search(r"\bthis\s*\.\s*" + re.escape(f) + r"\s*\.\s*(?:get|getAndRequireEquals|getAndAssertEquals)\s*\(", expr) for f in self.state_fields):
                result.add(match.group(1))
        return result

    def _compute_one(self, meth: object) -> _Summary:
        body, params = meth.body, list(meth.params)
        deps = self._deps(body, params)
        alias_paths = self._alias_paths(meth)
        state_locals = self._state_locals(body)
        effects: Dict[int, EffectFact] = {}
        constraints: Dict[int, str] = {}
        paths: Dict[int, Optional[Tuple[ProvenanceStep, ...]]] = {}

        def record_effect(expr: str, kind: str, offset: int) -> None:
            for ident in _IDENT.findall(expr):
                for index in deps.get(ident, set()):
                    effects.setdefault(index, EffectFact(kind, offset, expr.strip()))
                    prefix = alias_paths.get(ident, {}).get(index)
                    sink = ProvenanceStep(
                        "sink", f"{kind}: {expr.strip()}", meth.name,
                        self._line(meth, offset),
                    )
                    candidate = None if prefix is None else prefix + (sink,)
                    if index not in paths:
                        paths[index] = candidate
                    elif paths[index] != candidate:
                        paths[index] = None

        def record_send(match: re.Match[str]) -> None:
            segment, _ = _paren(body, match.end() - 1)
            amount = re.search(r"\bamount\s*:\s*([^,}]+)", segment)
            recipient = re.search(r"\bto\s*:\s*([^,}]+)", segment)
            if amount:
                record_effect(amount.group(1), "send_amount", match.start())
            elif re.search(r"(?:^|[,\s{])amount\s*(?:[,}]|$)", segment):
                record_effect("amount", "send_amount", match.start())
            if recipient:
                record_effect(recipient.group(1), "send_recipient", match.start())
            elif re.search(r"(?:^|[,\s{])to\s*(?:[,}]|$)", segment):
                record_effect("to", "send_recipient", match.start())

        for match in re.finditer(r"\bthis\s*\.\s*send\s*\(", body):
            record_send(match)

        # Account updates can transfer values either as a chained expression or
        # through a local initialized by AccountUpdate.create/createSigned.
        for match in re.finditer(
            r"\bAccountUpdate\s*\.\s*create(?:Signed)?\s*\([^;]*?\)\s*\.\s*send\s*\(",
            body,
        ):
            record_send(match)
        account_updates = {
            match.group(1)
            for match in _ASSIGN.finditer(body)
            if re.match(
                r"\s*AccountUpdate\s*\.\s*create(?:Signed)?\s*\(",
                match.group(2),
            )
        }
        for match in re.finditer(r"\b([A-Za-z_$][\w$]*)\s*\.\s*send\s*\(", body):
            if match.group(1) in account_updates:
                record_send(match)

        # Low-level transfers in current o1js examples debit an AccountUpdate
        # directly. Treat the debit as the same value-transfer sink as send().
        for match in re.finditer(
            r"\b((?:this\s*\.\s*(?:account|self))|[A-Za-z_$][\w$]*)\s*\.\s*"
            r"balance\s*\.\s*subInPlace\s*\(", body,
        ):
            receiver = re.sub(r"\s+", "", match.group(1))
            if receiver not in account_updates and receiver not in ("this.account", "this.self"):
                continue
            segment, _ = _paren(body, match.end() - 1)
            record_effect(segment, "send_amount", match.start())
        for match in re.finditer(
            r"\bAccountUpdate\s*\.\s*create(?:Signed)?\s*\([^;]*?\)\s*\.\s*"
            r"balance\s*\.\s*subInPlace\s*\(", body,
        ):
            segment, _ = _paren(body, match.end() - 1)
            record_effect(segment, "send_amount", match.start())

        for match in re.finditer(r"\bthis\s*\.\s*\w+\s*\.\s*set\s*\(", body):
            segment, _ = _paren(body, match.end() - 1)
            record_effect(segment, "state_set", match.start())

        for match in _ASSERT.finditer(body):
            inner, _ = _paren(body, match.end() - 1)
            whole = match.group(1) + " " + inner
            indexes: Set[int] = set()
            for ident in _IDENT.findall(whole):
                indexes |= deps.get(ident, set())
            bound = any(i in state_locals for i in _IDENT.findall(whole)) or any(
                re.search(r"\bthis\s*\.\s*" + re.escape(f) + r"\b", whole)
                for f in self.state_fields
            )
            level = "bound" if bound else "trivial"
            for index in indexes:
                if level == "bound" or constraints.get(index) != "bound":
                    constraints[index] = level

        # Compose callee summaries at every call site.  The effect offset is
        # the call in the entry body, giving rules stable, useful evidence.
        scope = getattr(meth, "semantic_scope", 0)
        for match in _CALL.finditer(body):
            callee = self._summaries.get((scope, match.group(1)))
            if callee is None:
                continue
            args_text, _ = _paren(body, match.end() - 1)
            args = _split_args(args_text)
            for callee_i, fact in callee.effects.items():
                if callee_i < len(args):
                    arg = args[callee_i].strip()
                    if re.fullmatch(r"[A-Za-z_$][\w$]*", arg):
                        for caller_i in deps.get(arg, set()):
                            effects.setdefault(caller_i, EffectFact(fact.kind, match.start(), fact.expression))
                            caller_path = alias_paths.get(arg, {}).get(caller_i)
                            callee_path = callee.paths.get(callee_i)
                            call = ProvenanceStep(
                                "call", f"this.{match.group(1)}({arg})", meth.name,
                                self._line(meth, match.start()),
                            )
                            target = self.methods[(scope, match.group(1))]
                            mapping = ProvenanceStep(
                                "parameter", f"{arg} -> {target.params[callee_i]}",
                                target.name, getattr(target, "start_line", 1),
                            )
                            candidate = (None if caller_path is None or callee_path is None
                                         else caller_path + (call, mapping) + callee_path)
                            if caller_i not in paths:
                                paths[caller_i] = candidate
                            elif paths[caller_i] != candidate:
                                paths[caller_i] = None
            for callee_i, level in callee.constraints.items():
                if callee_i < len(args):
                    # Only identity-preserving arguments transfer a constraint.
                    # Binding a relation such as check(a.add(b)) does not bind
                    # either operand independently.
                    arg = args[callee_i].strip()
                    if re.fullmatch(r"[A-Za-z_$][\w$]*", arg):
                        for caller_i in deps.get(arg, set()):
                            if level == "bound" or constraints.get(caller_i) != "bound":
                                constraints[caller_i] = level
        return _Summary(effects, constraints, paths)

    def _compute(self) -> None:
        # Monotone summaries converge quickly; the cap only protects malformed
        # adversarial source containing an enormous recursive call graph.
        for _ in range(max(1, len(self.methods) + 1)):
            changed = False
            for name, meth in self.methods.items():
                new = self._compute_one(meth)
                if new != self._summaries[name]:
                    self._summaries[name] = new
                    changed = True
            if not changed:
                break
