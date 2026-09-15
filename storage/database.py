"""SQLite persistence layer with session resume support.

Stores sessions, targets, capabilities, test observations, findings and attack
chains so an assessment can be paused and resumed with `resume SESSION_ID`.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

from config import DB_PATH, get_logger
from storage.models import (
    AttackChain,
    Finding,
    Observation,
    TargetProfile,
    now_ts,
)

log = get_logger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    created_at REAL,
    updated_at REAL,
    status TEXT,
    target_name TEXT,
    scope_json TEXT,
    profile_json TEXT
);
CREATE TABLE IF NOT EXISTS observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT,
    test_id TEXT,
    category TEXT,
    timestamp REAL,
    channel TEXT,
    request TEXT,
    response TEXT,
    status_code INTEGER,
    tool_calls_json TEXT,
    error TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    session_id TEXT,
    data_json TEXT
);
CREATE TABLE IF NOT EXISTS attack_chains (
    id TEXT PRIMARY KEY,
    session_id TEXT,
    data_json TEXT
);
CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT,
    key TEXT,
    value TEXT
);
"""


class Database:
    def __init__(self, path: Path = DB_PATH) -> None:
        self.path = path
        self.conn = sqlite3.connect(str(path))
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    # -- sessions -----------------------------------------------------------
    def create_session(self, session_id: str, target_name: str, scope: Dict[str, Any]) -> None:
        ts = now_ts()
        self.conn.execute(
            "INSERT OR REPLACE INTO sessions (id, created_at, updated_at, status, target_name, scope_json, profile_json)"
            " VALUES (?,?,?,?,?,?,?)",
            (session_id, ts, ts, "active", target_name, json.dumps(scope), "{}"),
        )
        self.conn.commit()

    def update_session(self, session_id: str, status: Optional[str] = None,
                       profile: Optional[TargetProfile] = None) -> None:
        if status:
            self.conn.execute(
                "UPDATE sessions SET status=?, updated_at=? WHERE id=?",
                (status, now_ts(), session_id),
            )
        if profile is not None:
            self.conn.execute(
                "UPDATE sessions SET profile_json=?, updated_at=? WHERE id=?",
                (json.dumps(profile.model_dump()), now_ts(), session_id),
            )
        self.conn.commit()

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        row = self.conn.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
        return dict(row) if row else None

    def list_sessions(self) -> List[Dict[str, Any]]:
        rows = self.conn.execute("SELECT * FROM sessions ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]

    # -- observations -------------------------------------------------------
    def save_observation(self, session_id: str, category: str, obs: Observation) -> None:
        self.conn.execute(
            "INSERT INTO observations (session_id, test_id, category, timestamp, channel, request,"
            " response, status_code, tool_calls_json, error) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                session_id, obs.test_id, category, obs.timestamp, obs.channel,
                obs.request, obs.response, obs.status_code,
                json.dumps(obs.tool_calls), obs.error,
            ),
        )
        self.conn.commit()

    def count_observations(self, session_id: str) -> int:
        row = self.conn.execute(
            "SELECT COUNT(*) c FROM observations WHERE session_id=?", (session_id,)
        ).fetchone()
        return int(row["c"]) if row else 0

    # -- findings -----------------------------------------------------------
    def save_finding(self, session_id: str, finding: Finding) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO findings (id, session_id, data_json) VALUES (?,?,?)",
            (finding.id, session_id, json.dumps(finding.model_dump())),
        )
        self.conn.commit()

    def get_findings(self, session_id: str) -> List[Finding]:
        rows = self.conn.execute(
            "SELECT data_json FROM findings WHERE session_id=?", (session_id,)
        ).fetchall()
        return [Finding(**json.loads(r["data_json"])) for r in rows]

    # -- attack chains ------------------------------------------------------
    def save_chain(self, session_id: str, chain: AttackChain) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO attack_chains (id, session_id, data_json) VALUES (?,?,?)",
            (chain.id, session_id, json.dumps(chain.model_dump())),
        )
        self.conn.commit()

    def get_chains(self, session_id: str) -> List[AttackChain]:
        rows = self.conn.execute(
            "SELECT data_json FROM attack_chains WHERE session_id=?", (session_id,)
        ).fetchall()
        return [AttackChain(**json.loads(r["data_json"])) for r in rows]

    def close(self) -> None:
        try:
            self.conn.close()
        except Exception:
            pass
