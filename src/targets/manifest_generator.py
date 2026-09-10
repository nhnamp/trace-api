from __future__ import annotations

import re
from pathlib import Path

import structlog
import yaml

from src.targets.manifest import LaunchManifest, LaunchSpec

logger = structlog.get_logger(__name__)

_SKIP_COMPONENTS = frozenset({
    "db_images", "db_image", ".devcontainer", "devcontainer",
    "test", "tests", "example", "examples", "doc", "docs",
    "mariadb", "mysql", "postgres", "postgresql", "redis", "mongo", "mongodb",
    "e2e", "ci", ".github", "sample", "samples",
})

_COMPOSE_NAMES = ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")

_HOST_PORT_BASE = 18000


def _score_dockerfile(rel_path: str) -> int:
    components = [c.lower() for c in rel_path.split("/")]
    dir_components = set(components[:-1])
    penalty = 0
    if dir_components & _SKIP_COMPONENTS:
        penalty += 1000
    penalty += rel_path.count("/") * 10
    if "/" not in rel_path:
        penalty -= 5
    return penalty


def _pick_dockerfile(cve_dir: Path) -> Path | None:
    candidates = sorted(cve_dir.rglob("Dockerfile"))
    if not candidates:
        return None
    scored = sorted(candidates, key=lambda p: _score_dockerfile(str(p.relative_to(cve_dir))))
    best = scored[0]
    if _score_dockerfile(str(best.relative_to(cve_dir))) >= 1000:
        return None
    return best


def _read_expose_port(dockerfile: Path) -> int | None:
    try:
        text = dockerfile.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None
    for line in text.splitlines():
        m = re.match(r"\s*EXPOSE\s+(.+)", line, re.IGNORECASE)
        if not m:
            continue
        for tok in m.group(1).split():
            tok = tok.split("/")[0]
            if tok.isdigit():
                return int(tok)
    return None


def _compose_host_port(compose_file: Path) -> int | None:
    try:
        data = yaml.safe_load(compose_file.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    ports: list[int] = []
    for svc in (data.get("services") or {}).values():
        if not isinstance(svc, dict):
            continue
        for entry in svc.get("ports", []) or []:
            m = re.match(r'"?(\d+):\d+"?', str(entry))
            if m:
                ports.append(int(m.group(1)))
    if not ports:
        return None
    for pref in (80, 8080, 9080, 3000, 8000):
        if pref in ports:
            return pref
    return sorted(ports)[0]


def generate_manifest(dataset_dir: str | Path) -> LaunchManifest:
    dataset_dir = Path(dataset_dir)
    cve_dirs = sorted(
        d for d in dataset_dir.iterdir()
        if d.is_dir() and d.name.startswith("CVE-")
    )

    specs: dict[str, LaunchSpec] = {}
    next_port = _HOST_PORT_BASE

    for cve_dir in cve_dirs:
        cve_id = cve_dir.name

        compose = next((cve_dir / n for n in _COMPOSE_NAMES if (cve_dir / n).exists()), None)
        if compose:
            hp = _compose_host_port(compose)
            specs[cve_id] = LaunchSpec(
                cve_id=cve_id, method="compose",
                compose_file=compose.name,
                host_port=hp,
                note="auto: top-level compose" + ("" if hp else " (host port unknown — verify)"),
                supported=hp is not None,
            )
            continue

        dockerfile = _pick_dockerfile(cve_dir)
        if dockerfile is not None:
            rel = str(dockerfile.relative_to(cve_dir))
            repo_root = rel.split("/")[0] if "/" in rel else "."
            container_port = _read_expose_port(dockerfile)
            host_port = next_port
            next_port += 1
            resolved = container_port is not None
            specs[cve_id] = LaunchSpec(
                cve_id=cve_id, method="dockerfile",
                dockerfile=rel,
                build_context=repo_root,
                host_port=host_port,
                container_port=container_port or 8080,
                note=(
                    "auto: dockerfile"
                    + ("" if resolved else " (no EXPOSE — container_port guessed 8080, verify)")
                ),
                supported=True,
            )
            continue

        specs[cve_id] = LaunchSpec(
            cve_id=cve_id, method="dockerfile", supported=False,
            note="auto: no compose/Dockerfile found — needs a launch recipe authored by hand",
        )

    logger.info(
        "manifest_generated",
        total=len(specs),
        supported=sum(1 for s in specs.values() if s.supported),
    )
    return LaunchManifest(specs=specs)
