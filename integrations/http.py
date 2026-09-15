"""HTTP integration for talking to a target AI agent.

Uses `requests` when available and transparently falls back to the stdlib
`urllib` so the platform has no hard third-party dependency. Every request and
response is captured verbatim for evidence.
"""
from __future__ import annotations

import json
from typing import Any, Dict, Optional, Tuple

from config import CONFIG, get_logger

log = get_logger(__name__)

try:
    import requests  # type: ignore

    _HAS_REQUESTS = True
except Exception:  # pragma: no cover
    _HAS_REQUESTS = False

import urllib.error
import urllib.request


class HttpResult:
    def __init__(self, status: int, body: str, headers: Dict[str, str], error: str = "") -> None:
        self.status = status
        self.body = body
        self.headers = headers
        self.error = error

    def json(self) -> Any:
        try:
            return json.loads(self.body)
        except Exception:
            return None


class HttpClient:
    def __init__(self, timeout: Optional[float] = None) -> None:
        self.timeout = timeout or CONFIG.request_timeout

    def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        json_body: Optional[Dict[str, Any]] = None,
    ) -> HttpResult:
        headers = dict(headers or {})
        data_bytes: Optional[bytes] = None
        if json_body is not None:
            data_bytes = json.dumps(json_body).encode("utf-8")
            headers.setdefault("Content-Type", "application/json")

        if _HAS_REQUESTS:
            try:
                resp = requests.request(
                    method, url, headers=headers,
                    data=data_bytes, timeout=self.timeout,
                )
                return HttpResult(resp.status_code, resp.text, dict(resp.headers))
            except Exception as exc:
                return HttpResult(0, "", {}, error=f"{type(exc).__name__}: {exc}")

        # urllib fallback
        try:
            req = urllib.request.Request(url, data=data_bytes, method=method.upper())
            for k, v in headers.items():
                req.add_header(k, v)
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
                body = resp.read().decode("utf-8", "replace")
                return HttpResult(resp.status, body, dict(resp.headers))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "replace") if hasattr(exc, "read") else ""
            return HttpResult(exc.code, body, dict(exc.headers or {}))
        except Exception as exc:
            return HttpResult(0, "", {}, error=f"{type(exc).__name__}: {exc}")

    def get(self, url: str, headers: Optional[Dict[str, str]] = None) -> HttpResult:
        return self.request("GET", url, headers=headers)

    def post_json(self, url: str, body: Dict[str, Any],
                  headers: Optional[Dict[str, str]] = None) -> HttpResult:
        return self.request("POST", url, headers=headers, json_body=body)


def probe(url: str, timeout: float = 5.0) -> Tuple[bool, int]:
    """Lightweight reachability probe."""
    client = HttpClient(timeout=timeout)
    res = client.get(url)
    return (res.status != 0 and not res.error, res.status)
