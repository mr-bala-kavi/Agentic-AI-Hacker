"""Core data models for the Agentic AI Hacker platform.

Uses Pydantic when available (richer validation) and transparently falls back
to lightweight dataclass-like shims so the platform runs even in a minimal
environment. All models are plain-data and JSON-serialisable.
"""
from __future__ import annotations

import enum
import time
import uuid
from typing import Any, Dict, List, Optional

try:  # Pydantic is preferred but optional.
    from pydantic import BaseModel, Field

    _HAS_PYDANTIC = True
except Exception:  # pragma: no cover - exercised only without pydantic
    _HAS_PYDANTIC = False

    def Field(default=None, **_kwargs):  # type: ignore
        return default

    class BaseModel:  # type: ignore
        """Minimal stand-in supporting the subset of Pydantic we use."""

        def __init__(self, **data: Any) -> None:
            for key, value in data.items():
                setattr(self, key, value)

        def model_dump(self) -> Dict[str, Any]:
            out: Dict[str, Any] = {}
            for key, value in self.__dict__.items():
                if isinstance(value, BaseModel):
                    out[key] = value.model_dump()
                elif isinstance(value, list):
                    out[key] = [
                        v.model_dump() if isinstance(v, BaseModel) else v for v in value
                    ]
                elif isinstance(value, enum.Enum):
                    out[key] = value.value
                else:
                    out[key] = value
            return out

        # Compatibility alias with older pydantic.
        def dict(self) -> Dict[str, Any]:  # noqa: D401
            return self.model_dump()


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def now_ts() -> float:
    return time.time()


class Severity(str, enum.Enum):
    INFO = "Informational"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

    @property
    def rank(self) -> int:
        return {
            "Informational": 0,
            "Low": 1,
            "Medium": 2,
            "High": 3,
            "Critical": 4,
        }[self.value]


class Confidence(str, enum.Enum):
    FALSE_POSITIVE = "False Positive"
    NEEDS_VERIFICATION = "Needs Verification"
    POTENTIAL = "Potential"
    CONFIRMED = "Confirmed"


class Classification(str, enum.Enum):
    OBSERVED = "Observed"
    INFERRED = "Inferred"
    UNKNOWN = "Unknown"


class Capability(BaseModel):
    """A discovered ability/attack-surface element of the target agent."""

    name: str = ""
    kind: str = ""  # chat | tool | mcp | rag | memory | file | browser | api | auth
    detail: str = ""
    classification: str = Classification.INFERRED.value
    evidence: str = ""


class TestCase(BaseModel):
    """A single planned security test."""

    __test__ = False  # tell pytest not to collect this data model as a test

    id: str = Field(default_factory=lambda: new_id("t"))
    category: str = ""
    name: str = ""
    channel: str = "chat"  # chat | http | mcp | indirect | tool | api
    payload: str = ""
    account: str = "user"  # which test account/role sends it
    setup: Dict[str, Any] = Field(default_factory=dict)
    detection: Dict[str, Any] = Field(default_factory=dict)
    severity_if_found: str = Severity.MEDIUM.value
    expected_behavior: str = ""
    risk: str = "safe"  # safe | low | risky | destructive

    def __init__(self, **data: Any) -> None:  # ensure defaults w/o pydantic
        data.setdefault("id", new_id("t"))
        data.setdefault("setup", {})
        data.setdefault("detection", {})
        super().__init__(**data)


class Observation(BaseModel):
    """Raw result of executing a test against the target."""

    test_id: str = ""
    timestamp: float = Field(default_factory=now_ts)
    channel: str = ""
    request: str = ""
    response: str = ""
    status_code: int = 0
    tool_calls: List[Dict[str, Any]] = Field(default_factory=list)
    error: str = ""

    def __init__(self, **data: Any) -> None:
        data.setdefault("timestamp", now_ts())
        data.setdefault("tool_calls", [])
        super().__init__(**data)


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: new_id("F"))
    title: str = ""
    category: str = ""
    severity: str = Severity.MEDIUM.value
    confidence: str = Confidence.NEEDS_VERIFICATION.value
    affected_component: str = ""
    attack_vector: str = ""
    preconditions: str = ""
    steps_to_reproduce: List[str] = Field(default_factory=list)
    observed_behavior: str = ""
    expected_behavior: str = ""
    security_impact: str = ""
    evidence: List[str] = Field(default_factory=list)
    root_cause: str = ""
    remediation: str = ""
    reproducibility: str = "Reproducible"
    test_id: str = ""

    def __init__(self, **data: Any) -> None:
        data.setdefault("id", new_id("F"))
        data.setdefault("steps_to_reproduce", [])
        data.setdefault("evidence", [])
        super().__init__(**data)


class AttackChain(BaseModel):
    id: str = Field(default_factory=lambda: new_id("AC"))
    name: str = ""
    steps: List[str] = Field(default_factory=list)
    finding_ids: List[str] = Field(default_factory=list)
    severity: str = Severity.HIGH.value
    narrative: str = ""

    def __init__(self, **data: Any) -> None:
        data.setdefault("id", new_id("AC"))
        data.setdefault("steps", [])
        data.setdefault("finding_ids", [])
        super().__init__(**data)


class TargetProfile(BaseModel):
    name: str = ""
    base_url: str = ""
    chat_path: str = "/chat"
    interface: str = "http"
    capabilities: List[Capability] = Field(default_factory=list)
    baseline: Dict[str, Any] = Field(default_factory=dict)

    def __init__(self, **data: Any) -> None:
        data.setdefault("capabilities", [])
        data.setdefault("baseline", {})
        super().__init__(**data)
