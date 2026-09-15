"""High-level orchestration helpers used by the CLI and self-test."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Dict, Optional

from config import get_logger
from agent.orchestrator import Orchestrator
from integrations.http import probe
from reporting.report_generator import ReportGenerator
from storage.database import Database
from targets.scope import Scope
from targets.target import Target

log = get_logger(__name__)


def run_assessment(target: Target, scope: Scope, *, generate_report: bool = True,
                   max_iterations: Optional[int] = None,
                   session_id: Optional[str] = None) -> Dict:
    db = Database()
    orch = Orchestrator(target, scope, session_id=session_id, db=db)
    result = orch.run_full(max_iterations=max_iterations)

    report_path = None
    if generate_report:
        rg = ReportGenerator(target.name, orch.session_id)
        report_path = rg.generate(
            profile=result["profile"],
            baseline=result["profile"].baseline,
            findings=result["findings"],
            chains=result["chains"],
            attack_model=result["attack_model"],
        )
    result["report_path"] = str(report_path) if report_path else None
    db.close()
    return result


def run_lab(port: int = 0, *, generate_report: bool = True) -> Dict:
    """Start the vulnerable mock agent in-process and assess it end-to-end."""
    from lab import mock_agent

    httpd, actual_port, _thread = mock_agent.start_in_thread(port)
    try:
        # wait for readiness
        for _ in range(50):
            ok, _ = probe(f"http://127.0.0.1:{actual_port}/health", timeout=2.0)
            if ok:
                break
            time.sleep(0.05)

        target = Target(
            name="SupportBot (vulnerable mock)",
            base_url=f"http://127.0.0.1:{actual_port}",
            chat_path="/chat",
            auth_header="X-Auth-Token",
            accounts={},
            interface="http",
        )
        # authorized test accounts (synthetic tokens)
        from targets.target import Account
        target.accounts = {
            "user": Account("user", "user-token", "U"),
            "admin": Account("admin", "admin-token", "A"),
            "anon": Account("anon", "", ""),
        }
        scope = Scope(
            allowed_hosts=["127.0.0.1"],
            allowed_ports=[actual_port],
            authorization="LAB: authorized self-test against bundled vulnerable mock",
            notes="Synthetic canaries only.",
        )
        result = run_assessment(target, scope, generate_report=generate_report)
        return result
    finally:
        try:
            httpd.shutdown()
            httpd.server_close()
        except Exception:
            pass


def load_target_file(path: str) -> Target:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return Target.from_dict(data)
