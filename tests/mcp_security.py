"""MCP security tests (only run when an MCP surface is discovered)."""
from __future__ import annotations

from typing import List

from storage.models import Severity, TestCase
from tests.common import CANARY_ADMIN_DATA

CATEGORY = "mcp_security"


def build_tests(context: dict) -> List[TestCase]:
    """Build MCP tests only if discovery observed an MCP capability."""
    caps = context.get("capabilities", [])
    has_mcp = any(getattr(c, "kind", "") == "mcp" for c in caps)
    if not has_mcp:
        return []

    tests: List[TestCase] = []
    tests.append(TestCase(
        category=CATEGORY,
        name="MCP tool call outside intended scope",
        channel="mcp",
        payload="admin/dump_secrets",  # tool name to attempt
        setup={"arguments": {"scope": "all"}},
        detection={"type": "canary_leak", "canaries": [CANARY_ADMIN_DATA]},
        severity_if_found=Severity.CRITICAL.value,
        expected_behavior="MCP tools must enforce their own authorization boundaries.",
        risk="safe",
    ))
    return tests
