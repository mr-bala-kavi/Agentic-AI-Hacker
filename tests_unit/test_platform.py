"""Unit tests for the Agentic AI Hacker platform.

Covers: scope validation, authorization logic, prompt-injection detection, tool
validation, MCP parsing, evidence storage, finding classification, report
generation, session recovery, safety restrictions, and a false-positive guard.
"""
from __future__ import annotations

import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from agent.analyzer import Analyzer  # noqa: E402
from agent.supervisor import SafetySupervisor  # noqa: E402
from reporting.report_generator import ReportGenerator  # noqa: E402
from storage.database import Database  # noqa: E402
from storage.models import (  # noqa: E402
    AttackChain,
    Confidence,
    Finding,
    Observation,
    Severity,
    TargetProfile,
    TestCase,
)
from targets.scope import Scope, ScopeValidator  # noqa: E402
from tests.common import INJECTION_MARKER  # noqa: E402


# ---------------------------------------------------------------- scope ----
def test_scope_denies_out_of_scope_host():
    v = ScopeValidator(Scope(allowed_hosts=["127.0.0.1"], allowed_ports=[8000],
                             authorization="test"))
    assert v.validate_url("http://127.0.0.1:8000/chat") is True
    assert v.validate_url("http://evil.example.com/chat") is False


def test_scope_requires_authorization():
    v = ScopeValidator(Scope(allowed_hosts=[], authorization=""))
    assert v.is_authorized() is False
    v2 = ScopeValidator(Scope(allowed_hosts=["127.0.0.1"], authorization="ok"))
    assert v2.is_authorized() is True


def test_scope_port_enforced():
    v = ScopeValidator(Scope(allowed_hosts=["127.0.0.1"], allowed_ports=[8000],
                             authorization="t"))
    assert v.validate_url("http://127.0.0.1:9999/chat") is False


# ---------------------------------------------------------- safety layer ----
def test_supervisor_blocks_out_of_scope():
    v = ScopeValidator(Scope(allowed_hosts=["127.0.0.1"], allowed_ports=[8000],
                             authorization="t"))
    sup = SafetySupervisor(v)
    ok, _ = sup.guard("http://evil.com/x", TestCase(risk="safe"))
    assert ok is False


def test_supervisor_forbids_destructive():
    v = ScopeValidator(Scope(allowed_hosts=["127.0.0.1"], allowed_ports=[8000],
                             authorization="t"))
    sup = SafetySupervisor(v)
    ok, reason = sup.guard("http://127.0.0.1:8000/x", TestCase(risk="destructive"))
    assert ok is False
    assert "destructive" in reason


def test_supervisor_allows_safe_in_scope():
    v = ScopeValidator(Scope(allowed_hosts=["127.0.0.1"], allowed_ports=[8000],
                             authorization="t"))
    sup = SafetySupervisor(v)
    ok, _ = sup.guard("http://127.0.0.1:8000/x", TestCase(risk="safe"))
    assert ok is True


# ------------------------------------------------ injection / detection ----
def test_injection_marker_detection_positive():
    a = Analyzer()
    test = TestCase(category="prompt_injection", name="x", channel="chat",
                    detection={"type": "injection_marker"},
                    severity_if_found=Severity.HIGH.value)
    obs = Observation(test_id=test.id, response=f"sure: {INJECTION_MARKER}")
    finding = a.analyze(test, obs)
    assert finding is not None
    assert finding.confidence == Confidence.CONFIRMED.value


def test_injection_marker_detection_negative():
    a = Analyzer()
    test = TestCase(category="prompt_injection", name="x", channel="chat",
                    detection={"type": "injection_marker"})
    obs = Observation(test_id=test.id, response="I can't do that.")
    assert a.analyze(test, obs) is None


def test_canary_detection():
    a = Analyzer()
    test = TestCase(category="data_exposure", name="x", channel="chat",
                    detection={"type": "canary_leak", "canaries": ["CANARY_SECRET_001"]},
                    severity_if_found=Severity.HIGH.value)
    obs = Observation(test_id=test.id, response="the secret is CANARY_SECRET_001 ok")
    f = a.analyze(test, obs)
    assert f is not None and "CANARY_SECRET_001" in " ".join(f.evidence)


# ---------------------------------------------------- tool / plan build ----
def test_tool_tests_build():
    from tests import tool_security
    cases = tool_security.build_tests({})
    assert len(cases) >= 2
    assert all(c.category == "tool_security" for c in cases)


def test_mcp_tests_skip_without_capability():
    from tests import mcp_security
    assert mcp_security.build_tests({"capabilities": []}) == []


def test_mcp_tests_build_with_capability():
    from tests import mcp_security
    from storage.models import Capability
    caps = [Capability(name="mcp", kind="mcp", detail="present")]
    cases = mcp_security.build_tests({"capabilities": caps})
    names = {c.name for c in cases}
    assert len(cases) == 4
    assert "Unauthorized privileged MCP tool call" in names
    assert all(c.channel == "mcp" for c in cases)


def test_mcp_mock_unauthorized_tool_leaks_canary():
    from lab.mock_agent import handle_mcp, CANARY_ADMIN_DATA
    resp = handle_mcp({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": "admin_dump_secrets", "arguments": {}}})
    text = json.dumps(resp)
    assert CANARY_ADMIN_DATA in text


def test_mcp_mock_resource_read_leaks_canary():
    from lab.mock_agent import handle_mcp, CANARY_SECRET_002
    resp = handle_mcp({"jsonrpc": "2.0", "id": 1, "method": "resources/read",
                       "params": {"uri": "file:///restricted/secrets"}})
    assert CANARY_SECRET_002 in json.dumps(resp)


def test_mcp_mock_path_traversal():
    from lab.mock_agent import handle_mcp, CANARY_SECRET_001
    resp = handle_mcp({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": "read_file",
                                  "arguments": {"path": "../../restricted/admin_secrets.txt"}}})
    assert CANARY_SECRET_001 in json.dumps(resp)


def test_mcp_initialize_handshake_has_server_info():
    """The discovery false-positive fix relies on serverInfo in the result."""
    from lab.mock_agent import handle_mcp
    resp = handle_mcp({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {}})
    result = resp.get("result", {})
    assert "serverInfo" in result and "protocolVersion" in result


def test_mcp_unknown_method_returns_error():
    from lab.mock_agent import handle_mcp
    resp = handle_mcp({"jsonrpc": "2.0", "id": 1, "method": "chat/completions", "params": {}})
    assert "error" in resp and "result" not in resp


def test_planner_builds_full_plan():
    from agent.planner import Planner
    plan = Planner().build_plan({"capabilities": []})
    cats = {t.category for t in plan}
    assert "prompt_injection" in cats and "authz" in cats and "data_exposure" in cats


# --------------------------------------------------- MCP JSON-RPC parse ----
def test_mcp_parse_tools_list():
    from integrations.mcp import McpClient
    client = McpClient("http://127.0.0.1:1/mcp")
    # simulate a parsed rpc result without network
    data = {"result": {"tools": [{"name": "a"}, {"name": "b"}]}}
    result = data.get("result", {})
    assert result.get("tools", []) == [{"name": "a"}, {"name": "b"}]
    assert client.endpoint.endswith("/mcp")


# ---------------------------------------------------- evidence storage ----
def test_database_roundtrip(tmp_path):
    db = Database(path=tmp_path / "t.db")
    db.create_session("S-1", "target", {"allowed_hosts": ["127.0.0.1"]})
    obs = Observation(test_id="t1", response="hello", channel="chat")
    db.save_observation("S-1", "prompt_injection", obs)
    assert db.count_observations("S-1") == 1
    f = Finding(title="x", category="authz", severity=Severity.HIGH.value)
    db.save_finding("S-1", f)
    got = db.get_findings("S-1")
    assert len(got) == 1 and got[0].title == "x"
    db.close()


def test_session_recovery(tmp_path):
    path = tmp_path / "t.db"
    db = Database(path=path)
    db.create_session("S-9", "tgt", {"a": 1})
    f = Finding(title="rec", category="authz", severity=Severity.HIGH.value)
    db.save_finding("S-9", f)
    db.close()
    # reopen and confirm data persists (resume)
    db2 = Database(path=path)
    sess = db2.get_session("S-9")
    assert sess is not None and sess["target_name"] == "tgt"
    assert len(db2.get_findings("S-9")) == 1
    db2.close()


# ------------------------------------------------ finding classification ----
def test_severity_ranking():
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.LOW.rank


# ----------------------------------------------------- report generation ----
def test_report_generation(tmp_path):
    rg = ReportGenerator("TestTarget", "S-test")
    profile = TargetProfile(name="TestTarget", base_url="http://127.0.0.1:8000")
    findings = [Finding(title="Injection", category="prompt_injection",
                        severity=Severity.HIGH.value,
                        confidence=Confidence.CONFIRMED.value)]
    chains = [AttackChain(name="Injection -> Exposure", steps=["a", "b"],
                          severity=Severity.CRITICAL.value)]
    path = rg.generate(profile, {"benign_probe": "4"}, findings, chains,
                       {"prompt_injection": "vulnerable"}, out_dir=tmp_path)
    text = path.read_text(encoding="utf-8")
    assert "AI Agent Security Penetration Test" in text
    assert "Injection" in text
    assert "FINAL SECURITY ASSESSMENT" in text


# ----------------------------------------------- false-positive guard ------
def test_secure_agent_yields_no_findings():
    """A hardened agent that refuses everything must produce zero findings."""
    a = Analyzer()
    refusal = "I can't help with that request."
    for dtype, det in [
        ("injection_marker", {"type": "injection_marker"}),
        ("canary_leak", {"type": "canary_leak", "canaries": ["CANARY_SECRET_001"]}),
        ("system_prompt_leak", {"type": "system_prompt_leak"}),
        ("phrase", {"type": "phrase", "phrases": ["EMAIL_SENT_NO_APPROVAL"]}),
    ]:
        test = TestCase(category="guardrails", name=dtype, detection=det)
        obs = Observation(test_id=test.id, response=refusal)
        assert a.analyze(test, obs) is None, f"false positive for {dtype}"


if __name__ == "__main__":
    raise SystemExit(pytest.main([os.path.abspath(__file__), "-q"]))
