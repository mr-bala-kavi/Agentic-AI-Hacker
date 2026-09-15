"""Test executor — turns a TestCase into a concrete request and Observation.

Handles multiple channels (chat/http/mcp/indirect) and multi-step setup
(`setup.pre` messages sent as other accounts, new-session isolation, etc.).
All traffic is scope-checked via the supervisor before it leaves the process.
"""
from __future__ import annotations

import json

from config import get_logger
from agent.supervisor import SafetySupervisor
from integrations.http import HttpClient
from integrations.mcp import McpClient
from storage.models import Observation, TestCase, now_ts
from targets.target import Target

log = get_logger(__name__)


class Executor:
    def __init__(self, target: Target, supervisor: SafetySupervisor) -> None:
        self.target = target
        self.supervisor = supervisor
        self.http = HttpClient()

    def _headers(self, role: str) -> dict:
        acct = self.target.account(role)
        if acct:
            return acct.auth_headers(self.target.auth_header)
        return {}

    def _chat(self, message: str, role: str, session_id: str) -> tuple:
        url = self.target.chat_url
        allowed, reason = self.supervisor.guard(url, TestCase(risk="safe"))
        if not allowed:
            return 0, f"[BLOCKED BY SUPERVISOR: {reason}]", {}
        headers = self._headers(role)
        res = self.http.post_json(url, {"message": message, "session_id": session_id}, headers)
        body = res.body
        data = res.json()
        text = body
        if isinstance(data, dict):
            text = data.get("reply", data.get("response", json.dumps(data)))
        return res.status, text, data if isinstance(data, dict) else {}

    def execute(self, test: TestCase, session_prefix: str = "sess") -> Observation:
        obs = Observation(test_id=test.id, channel=test.channel, timestamp=now_ts())

        # MCP channel.
        if test.channel == "mcp":
            url = self.target.mcp_url
            allowed, reason = self.supervisor.guard(url, test)
            if not allowed:
                obs.response = f"[BLOCKED BY SUPERVISOR: {reason}]"
                return obs
            try:
                mcp = McpClient(url)
                result = mcp.call_tool(test.payload, test.setup.get("arguments", {}))
                obs.request = json.dumps({"tool": test.payload, "args": test.setup.get("arguments", {})})
                obs.response = json.dumps(result)
                obs.tool_calls = [{"name": test.payload, "arguments": test.setup.get("arguments", {})}]
                obs.status_code = 200
            except Exception as exc:
                obs.error = f"{type(exc).__name__}: {exc}"
            return obs

        # Chat / indirect / http channels all use the chat endpoint.
        session_id = f"{session_prefix}-{test.id}"
        if test.setup.get("new_session"):
            session_id = f"{session_prefix}-iso-{test.id}"

        # Pre-steps (e.g. another user plants a note first).
        pre = test.setup.get("pre", [])
        pre_log = []
        for step in pre:
            p_role = step.get("account", "user")
            p_sid = session_id if not test.setup.get("new_session") else f"{session_prefix}-{p_role}-pre"
            status, text, _ = self._chat(step["message"], p_role, p_sid)
            pre_log.append({"role": p_role, "message": step["message"], "reply": text[:200]})

        status, text, data = self._chat(test.payload, test.account, session_id)
        obs.request = json.dumps({
            "account": test.account,
            "session_id": session_id,
            "pre_steps": pre_log,
            "message": test.payload,
        })
        obs.response = text
        obs.status_code = status
        if isinstance(data, dict) and data.get("tool_calls"):
            obs.tool_calls = data["tool_calls"]
        return obs
