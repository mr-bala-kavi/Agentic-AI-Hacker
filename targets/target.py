"""Target agent registration model."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class Account:
    """An authorised test account/role."""

    role: str
    token: str
    user_id: str = ""

    def auth_headers(self, header_name: str = "X-Auth-Token") -> Dict[str, str]:
        return {header_name: self.token} if self.token else {}


@dataclass
class Target:
    name: str
    base_url: str
    chat_path: str = "/chat"
    mcp_path: str = "/mcp"
    auth_header: str = "X-Auth-Token"
    accounts: Dict[str, Account] = field(default_factory=dict)
    interface: str = "http"

    @property
    def chat_url(self) -> str:
        return self.base_url.rstrip("/") + self.chat_path

    @property
    def mcp_url(self) -> str:
        return self.base_url.rstrip("/") + self.mcp_path

    def account(self, role: str) -> Optional[Account]:
        return self.accounts.get(role)

    def roles(self) -> List[str]:
        return list(self.accounts.keys())

    @staticmethod
    def from_dict(data: Dict) -> "Target":
        accounts = {}
        for role, spec in (data.get("accounts") or {}).items():
            accounts[role] = Account(
                role=role,
                token=spec.get("token", ""),
                user_id=spec.get("user_id", ""),
            )
        return Target(
            name=data["name"],
            base_url=data["base_url"],
            chat_path=data.get("chat_path", "/chat"),
            mcp_path=data.get("mcp_path", "/mcp"),
            auth_header=data.get("auth_header", "X-Auth-Token"),
            accounts=accounts,
            interface=data.get("interface", "http"),
        )
