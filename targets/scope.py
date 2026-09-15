"""Scope validation — the core safety boundary.

Every outbound action is validated against an explicitly declared scope. The
LLM/planner cannot mutate scope at runtime; only the operator-provided scope
object is honoured. Anything outside the declared hosts/paths is denied.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List
from urllib.parse import urlparse

from config import get_logger

log = get_logger(__name__)


@dataclass
class Scope:
    allowed_hosts: List[str] = field(default_factory=list)
    allowed_ports: List[int] = field(default_factory=list)
    authorization: str = ""
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "allowed_hosts": self.allowed_hosts,
            "allowed_ports": self.allowed_ports,
            "authorization": self.authorization,
            "notes": self.notes,
        }


class ScopeValidator:
    def __init__(self, scope: Scope) -> None:
        self.scope = scope

    def is_authorized(self) -> bool:
        return bool(self.scope.authorization) and bool(self.scope.allowed_hosts)

    def validate_url(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
        except Exception:
            return False
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if host not in self.scope.allowed_hosts:
            log.warning("SCOPE DENY: host %s not in declared scope", host)
            return False
        if self.scope.allowed_ports and port not in self.scope.allowed_ports:
            log.warning("SCOPE DENY: port %s not in declared scope", port)
            return False
        return True

    def require(self, url: str) -> None:
        if not self.validate_url(url):
            raise PermissionError(f"Action against {url} is outside declared scope")
