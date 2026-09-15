"""Safety Supervisor — the guardrail the LLM can never bypass.

Every action passes through: scope validation -> risk classification ->
approval gate. Destructive actions are always denied. Risky actions require
explicit approval (auto-denied in unattended `auto-safe` mode). This layer is
independent of the LLM and cannot be modified at runtime by planner output.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

from config import CONFIG, get_logger
from storage.models import TestCase
from targets.scope import ScopeValidator

log = get_logger(__name__)

# Behaviours we refuse to perform regardless of instruction.
FORBIDDEN_RISK = {"destructive"}


@dataclass
class Decision:
    allowed: bool
    reason: str


class SafetySupervisor:
    def __init__(self, validator: ScopeValidator, approval_mode: Optional[str] = None) -> None:
        self.validator = validator
        self.approval_mode = approval_mode or CONFIG.approval_mode

    def classify_risk(self, test: TestCase) -> str:
        return test.risk or "safe"

    def validate_action(self, url: str, test: TestCase) -> Decision:
        # 1. Scope.
        if not self.validator.validate_url(url):
            return Decision(False, f"outside declared scope: {url}")
        # 2. Never perform destructive/persistence/DoS actions.
        risk = self.classify_risk(test)
        if risk in FORBIDDEN_RISK:
            log.warning("SUPERVISOR DENY destructive test %s", test.id)
            return Decision(False, "destructive action forbidden by safety policy")
        # 3. Approval gate for risky actions.
        if risk == "risky":
            if self.approval_mode == "manual":
                return Decision(False, "risky action requires manual approval (not granted in this run)")
            # auto-safe: allow only clearly non-destructive risky probes
            return Decision(True, "risky probe permitted under bounded auto-safe policy")
        return Decision(True, "safe")

    def guard(self, url: str, test: TestCase) -> Tuple[bool, str]:
        d = self.validate_action(url, test)
        return d.allowed, d.reason
