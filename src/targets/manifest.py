from __future__ import annotations

from pathlib import Path

import structlog
import yaml
from pydantic import BaseModel

logger = structlog.get_logger(__name__)

DEFAULT_MANIFEST_NAME = "manifest.yaml"


class LaunchSpec(BaseModel):
    cve_id: str
    method: str = "dockerfile"
    supported: bool = True

    compose_file: str | None = None

    dockerfile: str | None = None
    build_context: str | None = None
    image: str | None = None
    run_args: list[str] = []

    host_port: int | None = None
    container_port: int | None = None

    health_path: str = "/"
    startup_timeout_s: int = 90
    build_timeout_s: int = 600

    env: dict[str, str] = {}
    note: str = ""

    def base_url(self) -> str | None:
        if self.host_port is None:
            return None
        return f"http://127.0.0.1:{self.host_port}"

    def health_url(self) -> str | None:
        base = self.base_url()
        if base is None:
            return None
        path = self.health_path if self.health_path.startswith("/") else "/" + self.health_path
        return base + path


class LaunchManifest(BaseModel):
    specs: dict[str, LaunchSpec] = {}

    @classmethod
    def load(cls, path: str | Path) -> "LaunchManifest":
        path = Path(path)
        if not path.exists():
            logger.info("manifest_absent", path=str(path))
            return cls()
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            logger.warning("manifest_parse_failed", path=str(path), error=str(exc))
            return cls()

        entries = data.get("cves", data) if isinstance(data, dict) else {}
        specs: dict[str, LaunchSpec] = {}
        for cve_id, raw in (entries or {}).items():
            if not isinstance(raw, dict):
                continue
            raw = {**raw, "cve_id": cve_id}
            try:
                specs[cve_id] = LaunchSpec.model_validate(raw)
            except Exception as exc:  # noqa: BLE001 — one bad entry must not sink the rest
                logger.warning("manifest_entry_invalid", cve_id=cve_id, error=str(exc))
        logger.info("manifest_loaded", path=str(path), entries=len(specs))
        return cls(specs=specs)

    @classmethod
    def default_path(cls, dataset_dir: str | Path) -> Path:
        return Path(dataset_dir) / DEFAULT_MANIFEST_NAME

    def get(self, cve_id: str) -> LaunchSpec | None:
        return self.specs.get(cve_id)

    def save(self, path: str | Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "cves": {
                cve_id: spec.model_dump(exclude={"cve_id"}, exclude_defaults=False)
                for cve_id, spec in sorted(self.specs.items())
            }
        }
        path.write_text(
            yaml.safe_dump(payload, sort_keys=False, default_flow_style=False),
            encoding="utf-8",
        )
        logger.info("manifest_saved", path=str(path), entries=len(self.specs))
        return path
