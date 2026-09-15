"""Central configuration and structured logging setup.

Loads settings from environment variables (and an optional .env file) without
ever printing secrets. API keys are read lazily and never logged.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parent
EVIDENCE_DIR = ROOT / "evidence"
LOGS_DIR = ROOT / "logs"
REPORTS_DIR = ROOT / "reports"
PROMPTS_DIR = ROOT / "prompts"
WORKSPACE = ROOT / "ai-agent-pentest"
DB_PATH = ROOT / "agentic_hacker.db"

SECRET_KEYS = ("OPENAI_API_KEY", "ANTHROPIC_API_KEY")


def _load_dotenv() -> None:
    """Very small .env loader (KEY=VALUE lines). Optional, no dependency."""
    env_file = ROOT / ".env"
    if not env_file.exists():
        return
    try:
        for line in env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))
    except Exception:
        pass


class Config:
    def __init__(self) -> None:
        _load_dotenv()
        self.llm_provider = os.getenv("LLM_PROVIDER", "heuristic").lower()
        self.llm_model = os.getenv("LLM_MODEL", "")
        self.request_timeout = float(os.getenv("REQUEST_TIMEOUT", "15"))
        self.max_test_iterations = int(os.getenv("MAX_TEST_ITERATIONS", "200"))
        self.approval_mode = os.getenv("APPROVAL_MODE", "auto-safe")  # auto-safe|manual
        for d in (EVIDENCE_DIR, LOGS_DIR, REPORTS_DIR, PROMPTS_DIR, WORKSPACE):
            d.mkdir(parents=True, exist_ok=True)

    def get_secret(self, key: str) -> Optional[str]:
        """Fetch a secret value. Never logged, never echoed."""
        return os.getenv(key)

    def has_llm_key(self) -> bool:
        if self.llm_provider == "openai":
            return bool(self.get_secret("OPENAI_API_KEY"))
        if self.llm_provider == "anthropic":
            return bool(self.get_secret("ANTHROPIC_API_KEY"))
        return True  # heuristic provider needs no key


class RedactingFilter(logging.Filter):
    """Guarantees secret values never reach the logs."""

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        msg = record.getMessage()
        for key in SECRET_KEYS:
            val = os.getenv(key)
            if val and val in msg:
                record.msg = msg.replace(val, "***REDACTED***")
                record.args = ()
        return True


def get_logger(name: str = "agentic_hacker") -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    fh = logging.FileHandler(LOGS_DIR / "session.log", encoding="utf-8")
    fmt = logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s")
    fh.setFormatter(fmt)
    fh.addFilter(RedactingFilter())
    logger.addHandler(fh)
    logger.propagate = False
    return logger


CONFIG = Config()
