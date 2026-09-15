"""Generic REST API integration used to probe backend endpoints exposed via the
agent (for IDOR / broken-authorization style checks through the agent's API).
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from integrations.http import HttpClient, HttpResult


class ApiClient:
    def __init__(self, base_url: str, timeout: Optional[float] = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.http = HttpClient(timeout=timeout)

    def call(self, method: str, path: str, headers: Optional[Dict[str, str]] = None,
             body: Optional[Dict[str, Any]] = None) -> HttpResult:
        url = self.base_url + (path if path.startswith("/") else "/" + path)
        return self.http.request(method, url, headers=headers, json_body=body)
