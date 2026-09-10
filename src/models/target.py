from __future__ import annotations

from pydantic import BaseModel


class TargetInfo(BaseModel):
    url: str
    cve_id: str | None = None
    metadata: dict = {}
