from __future__ import annotations

import json
import re
import uuid
from pathlib import Path

import structlog

from src.config.settings import SessionConfig
from src.models.session import SessionState
from src.models.target import TargetInfo

logger = structlog.get_logger(__name__)


class SessionNotFoundError(Exception):
    def __init__(self, session_id: str):
        self.session_id = session_id
        super().__init__(f"Session not found: {session_id}")


class SessionManager:
    def __init__(self, config: SessionConfig):
        self.base_dir = Path(config.session_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _session_dir(self, session_id: str) -> Path:
        return self.base_dir / f"sess-{session_id}"

    def _session_file(self, session_id: str) -> Path:
        return self._session_dir(session_id) / "session.json"

    @staticmethod
    def _slugify_cve(cve_id: str) -> str:
        slug = re.sub(r"[^A-Za-z0-9-]+", "-", cve_id).strip("-")
        return slug.upper()

    def _allocate_session_id(self, target: TargetInfo) -> str:
        base = self._slugify_cve(target.cve_id) if target.cve_id else ""
        if not base:
            return uuid.uuid4().hex[:12]

        if not self._session_dir(base).exists():
            return base

        suffix = 2
        while self._session_dir(f"{base}-{suffix}").exists():
            suffix += 1
        return f"{base}-{suffix}"

    def create(self, target: TargetInfo) -> SessionState:
        session_id = self._allocate_session_id(target)
        session = SessionState(
            session_id=session_id,
            target=target,
        )
        self.save(session)
        logger.info(
            "session_created",
            session_id=session_id,
            target_url=target.url,
            cve_id=target.cve_id,
        )
        return session

    def save(self, session: SessionState) -> Path:
        session.touch()
        session_dir = self._session_dir(session.session_id)
        session_dir.mkdir(parents=True, exist_ok=True)
        session_file = self._session_file(session.session_id)
        session_file.write_text(
            session.model_dump_json(indent=2),
            encoding="utf-8",
        )
        logger.debug(
            "session_saved",
            session_id=session.session_id,
            path=str(session_file),
        )
        return session_file

    def load(self, session_id: str) -> SessionState:
        session_file = self._session_file(session_id)
        if not session_file.exists():
            raise SessionNotFoundError(session_id)
        data = json.loads(session_file.read_text(encoding="utf-8"))
        session = SessionState(**data)
        logger.debug("session_loaded", session_id=session_id)
        return session

    def list_sessions(self) -> list[dict]:
        sessions = []
        if not self.base_dir.exists():
            return sessions
        for entry in sorted(self.base_dir.iterdir()):
            if not entry.is_dir() or not entry.name.startswith("sess-"):
                continue
            session_id = entry.name.removeprefix("sess-")
            session_file = entry / "session.json"
            if not session_file.exists():
                continue
            try:
                data = json.loads(session_file.read_text(encoding="utf-8"))
                sessions.append(
                    {
                        "session_id": session_id,
                        "target_url": data.get("target", {}).get("url", ""),
                        "cve_id": data.get("target", {}).get("cve_id"),
                        "state": data.get("fsm_state", ""),
                        "created_at": data.get("created_at", ""),
                        "updated_at": data.get("updated_at", ""),
                    }
                )
            except (json.JSONDecodeError, KeyError):
                logger.warning("corrupt_session_file", path=str(session_file))
        return sessions

    def exists(self, session_id: str) -> bool:
        return self._session_file(session_id).exists()

    def delete(self, session_id: str) -> None:
        session_dir = self._session_dir(session_id)
        if not session_dir.exists():
            raise SessionNotFoundError(session_id)
        import shutil

        shutil.rmtree(session_dir)
        logger.info("session_deleted", session_id=session_id)

    def get_session_dir(self, session_id: str) -> Path:
        return self._session_dir(session_id)
