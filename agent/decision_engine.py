"""Decision engine — maintains the attack model and adapts test selection.

Implements the OBSERVE -> UPDATE_ATTACK_MODEL -> SELECT_NEXT_TEST logic. It
tracks which categories have succeeded/failed and can escalate: e.g. once
prompt injection works, prioritise data-exposure and tool tests; avoid
repeating an identical failed action.
"""
from __future__ import annotations

from typing import Dict, List, Set

from config import get_logger
from storage.models import Finding, TestCase

log = get_logger(__name__)


class DecisionEngine:
    def __init__(self) -> None:
        self.succeeded_categories: Set[str] = set()
        self.failed_signatures: Set[str] = set()
        self.attack_model: Dict[str, str] = {}
        self.executed: Set[str] = set()

    def signature(self, test: TestCase) -> str:
        return f"{test.category}:{test.name}:{test.account}"

    def should_run(self, test: TestCase) -> bool:
        sig = self.signature(test)
        if sig in self.executed:
            return False  # never repeat an identical action blindly
        return True

    def record(self, test: TestCase, finding: Finding | None) -> None:
        sig = self.signature(test)
        self.executed.add(sig)
        if finding is not None:
            self.succeeded_categories.add(test.category)
            self.attack_model[test.category] = "vulnerable"
        else:
            self.failed_signatures.add(sig)
            self.attack_model.setdefault(test.category, "resistant")

    def prioritize(self, plan: List[TestCase]) -> List[TestCase]:
        """Escalation heuristic: if injection worked, push exfil/tool/authz earlier."""
        escalate = {"data_exposure", "tool_security", "authz"}
        if "prompt_injection" in self.succeeded_categories:
            plan.sort(key=lambda t: 0 if t.category in escalate else 1)
        return plan

    def summary(self) -> Dict[str, str]:
        return dict(self.attack_model)
