"""Adaptive test planner.

Aggregates test cases from every security-test module, ordered by an LLM-advised
(or heuristic) priority. The plan is only a *suggestion queue*; the decision
engine may re-order it as the attack model updates.
"""
from __future__ import annotations

from typing import Callable, Dict, List

from config import get_logger
from llm.provider import get_provider
from storage.models import TestCase
from tests import (
    authz,
    data_exposure,
    excessive_agency,
    guardrails,
    instruction_disclosure,
    mcp_security,
    memory_security,
    prompt_injection,
    rag_security,
    tool_security,
)

log = get_logger(__name__)

# category name -> builder
BUILDERS: Dict[str, Callable[[dict], List[TestCase]]] = {
    "prompt_injection": prompt_injection.build_tests,
    "instruction_disclosure": instruction_disclosure.build_tests,
    "tool_security": tool_security.build_tests,
    "excessive_agency": excessive_agency.build_tests,
    "authz": authz.build_tests,
    "memory_security": memory_security.build_tests,
    "rag_security": rag_security.build_tests,
    "mcp_security": mcp_security.build_tests,
    "data_exposure": data_exposure.build_tests,
    "guardrails": guardrails.build_tests,
}


class Planner:
    def __init__(self) -> None:
        self.llm = get_provider()

    def _priority_order(self, context: dict) -> List[str]:
        cap_kinds = ",".join(sorted({getattr(c, "kind", "") for c in context.get("capabilities", [])}))
        hint = self.llm.complete(
            prompt=f"capabilities: {cap_kinds}. categories: {','.join(BUILDERS)}",
            system="Rank AI-agent security test categories by likely impact.",
        )
        order = [c for c in BUILDERS if c in hint]
        # Ensure every category is represented even if the hint is partial.
        for c in BUILDERS:
            if c not in order:
                order.append(c)
        return order

    def build_plan(self, context: dict) -> List[TestCase]:
        order = self._priority_order(context)
        plan: List[TestCase] = []
        for category in order:
            builder = BUILDERS[category]
            try:
                cases = builder(context)
                plan.extend(cases)
            except Exception as exc:  # pragma: no cover
                log.warning("planner: builder %s failed: %s", category, exc)
        log.info("Planner built %d test cases across %d categories", len(plan), len(order))
        return plan
