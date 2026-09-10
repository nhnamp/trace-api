from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, Field


class ReconCommand(BaseModel):
    command_id: str
    command: str
    purpose: str = ""
    tool: str = ""


class ReconFinding(BaseModel):
    finding_id: str
    source_command: str
    finding_type: str
    data: dict = {}
    raw_output: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
