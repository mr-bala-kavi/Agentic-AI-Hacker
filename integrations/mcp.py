"""Minimal MCP (Model Context Protocol) client for trust-boundary testing.

Supports HTTP JSON-RPC MCP endpoints. Used to enumerate tools/resources and to
test whether the agent can be driven to call MCP tools outside intended scope.
Gracefully reports "not present" when the target has no MCP surface.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from config import get_logger
from integrations.http import HttpClient

log = get_logger(__name__)


class McpClient:
    def __init__(self, endpoint: str, timeout: Optional[float] = None) -> None:
        self.endpoint = endpoint
        self.http = HttpClient(timeout=timeout)
        self._id = 0

    def _rpc(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        self._id += 1
        payload = {"jsonrpc": "2.0", "id": self._id, "method": method, "params": params or {}}
        res = self.http.post_json(self.endpoint, payload)
        data = res.json()
        if isinstance(data, dict):
            return data
        return {"error": {"message": res.error or "non-json response", "raw": res.body[:400]}}

    def is_present(self) -> bool:
        """Validate a real MCP surface via the initialize handshake.

        A generic HTTP endpoint that merely returns 200 is NOT accepted; the
        response must be a JSON-RPC result carrying MCP server metadata. This
        avoids false-positives from chat endpoints that answer any POST.
        """
        data = self._rpc("initialize", {})
        result = data.get("result", {}) if isinstance(data, dict) else {}
        if not isinstance(result, dict):
            return False
        return any(k in result for k in ("serverInfo", "protocolVersion", "capabilities"))

    def list_tools(self) -> List[Dict[str, Any]]:
        data = self._rpc("tools/list")
        result = data.get("result", {}) if isinstance(data, dict) else {}
        return result.get("tools", []) if isinstance(result, dict) else []

    def list_resources(self) -> List[Dict[str, Any]]:
        data = self._rpc("resources/list")
        result = data.get("result", {}) if isinstance(data, dict) else {}
        return result.get("resources", []) if isinstance(result, dict) else []

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        return self._rpc("tools/call", {"name": name, "arguments": arguments})

    def read_resource(self, uri: str) -> Dict[str, Any]:
        return self._rpc("resources/read", {"uri": uri})
