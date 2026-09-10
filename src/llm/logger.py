from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import structlog

from src.models.session import SessionState

logger = structlog.get_logger(__name__)


class LLMCallRecord:
    def __init__(
        self,
        *,
        model: str,
        purpose: str,
        messages: list[dict],
        response_content: str,
        usage: dict | None = None,
        latency_ms: int = 0,
    ):
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.model = model
        self.purpose = purpose
        self.messages = messages
        self.response_content = response_content
        self.usage = usage or {}
        self.latency_ms = latency_ms

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "model": self.model,
            "purpose": self.purpose,
            "messages": self.messages,
            "response_content": self.response_content,
            "usage": self.usage,
            "latency_ms": self.latency_ms,
        }


class LLMLogger:
    def __init__(self, log_dir: Path):
        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)

    @classmethod
    def for_session(cls, session: SessionState, base_dir: Path) -> LLMLogger:
        log_dir = base_dir / f"sess-{session.session_id}"
        return cls(log_dir)

    def log_call(self, record: LLMCallRecord) -> None:
        log_file = self.log_dir / "llm_calls.jsonl"
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(record.to_dict(), ensure_ascii=False) + "\n")
        logger.debug(
            "llm_call_logged",
            model=record.model,
            purpose=record.purpose,
            latency_ms=record.latency_ms,
            tokens=record.usage,
        )

    def read_calls(self) -> list[dict]:
        log_file = self.log_dir / "llm_calls.jsonl"
        if not log_file.exists():
            return []
        records = []
        for line in log_file.read_text(encoding="utf-8").strip().splitlines():
            if line:
                records.append(json.loads(line))
        return records
