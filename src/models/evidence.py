from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


class StepStatus(str, Enum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    FALLBACK_USED = "FALLBACK_USED"


class HTTPResponseCapture(BaseModel):
    status_code: int
    headers: dict[str, str] = {}
    body: str = ""
    content_type: str = ""


class ExploitStepResult(BaseModel):
    step_id: str
    step_description: str
    command: str
    input_variables: dict = {}
    status: StepStatus
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    http_response: HTTPResponseCapture | None = None
    artifacts: list[str] = []
    is_evidence: bool = False
    evidence_summary: str | None = None
    duration_ms: int = 0
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
