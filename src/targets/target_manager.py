from __future__ import annotations

import asyncio
import re
from enum import Enum
from pathlib import Path

import structlog
from pydantic import BaseModel

from src.targets.manifest import LaunchManifest, LaunchSpec

logger = structlog.get_logger(__name__)


class LaunchMethod(str, Enum):
    DOCKER_COMPOSE = "docker_compose"
    DOCKERFILE = "dockerfile"
    IMAGE = "image"
    SCRIPT = "script"
    UNKNOWN = "unknown"


class TargetEnvironment(BaseModel):
    cve_id: str
    directory: str
    launch_method: LaunchMethod
    compose_file: str | None = None
    dockerfile_path: str | None = None
    script_path: str | None = None
    target_url: str | None = None
    ports: list[int] = []
    running: bool = False

    from_manifest: bool = False
    supported: bool = True
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


class TargetManager:
    def __init__(
        self, dataset_dir: str | Path, manifest_path: str | Path | None = None
    ) -> None:
        self.dataset_dir = Path(dataset_dir)
        mpath = Path(manifest_path) if manifest_path else LaunchManifest.default_path(self.dataset_dir)
        self.manifest = LaunchManifest.load(mpath)

    def discover_environments(self) -> list[TargetEnvironment]:
        if not self.dataset_dir.exists():
            logger.warning("dataset_dir_missing", path=str(self.dataset_dir))
            return []
        envs = []
        for entry in sorted(self.dataset_dir.iterdir()):
            if not entry.is_dir() or not entry.name.startswith("CVE-"):
                continue
            env = self._detect_environment(entry)
            if env.launch_method != LaunchMethod.UNKNOWN:
                envs.append(env)
        logger.info("environments_discovered", count=len(envs))
        return envs

    def get_environment(self, cve_id: str) -> TargetEnvironment:
        cve_dir = self.dataset_dir / cve_id
        if not cve_dir.exists():
            raise FileNotFoundError(f"CVE directory not found: {cve_dir}")
        return self._detect_environment(cve_dir)

    def _detect_environment(self, cve_dir: Path) -> TargetEnvironment:
        cve_id = cve_dir.name

        spec = self.manifest.get(cve_id)
        if spec is not None:
            return self._env_from_spec(cve_dir, spec)

        compose_file = self._find_compose_file(cve_dir)
        if compose_file:
            ports = self._extract_compose_ports(compose_file)
            url = self._infer_url_from_ports(ports)
            return TargetEnvironment(
                cve_id=cve_id,
                directory=str(cve_dir),
                launch_method=LaunchMethod.DOCKER_COMPOSE,
                compose_file=str(compose_file),
                target_url=url,
                ports=ports,
            )

        dockerfile = self._find_dockerfile(cve_dir)
        if dockerfile:
            return TargetEnvironment(
                cve_id=cve_id,
                directory=str(cve_dir),
                launch_method=LaunchMethod.DOCKERFILE,
                dockerfile_path=str(dockerfile),
            )

        script = self._find_launch_script(cve_dir)
        if script:
            return TargetEnvironment(
                cve_id=cve_id,
                directory=str(cve_dir),
                launch_method=LaunchMethod.SCRIPT,
                script_path=str(script),
            )

        return TargetEnvironment(
            cve_id=cve_id,
            directory=str(cve_dir),
            launch_method=LaunchMethod.UNKNOWN,
        )

    def _env_from_spec(self, cve_dir: Path, spec: LaunchSpec) -> TargetEnvironment:
        method_map = {
            "compose": LaunchMethod.DOCKER_COMPOSE,
            "dockerfile": LaunchMethod.DOCKERFILE,
            "image": LaunchMethod.IMAGE,
        }
        method = method_map.get(spec.method, LaunchMethod.UNKNOWN)

        def _resolve(rel: str | None) -> str | None:
            return str(cve_dir / rel) if rel else None

        return TargetEnvironment(
            cve_id=spec.cve_id,
            directory=str(cve_dir),
            launch_method=method,
            compose_file=_resolve(spec.compose_file),
            dockerfile_path=_resolve(spec.dockerfile),
            build_context=_resolve(spec.build_context) or str(cve_dir),
            image=spec.image,
            run_args=list(spec.run_args),
            host_port=spec.host_port,
            container_port=spec.container_port,
            ports=[spec.host_port] if spec.host_port else [],
            target_url=spec.base_url(),
            health_path=spec.health_path,
            startup_timeout_s=spec.startup_timeout_s,
            build_timeout_s=spec.build_timeout_s,
            env=dict(spec.env),
            note=spec.note,
            supported=spec.supported,
            from_manifest=True,
        )

    def _find_compose_file(self, cve_dir: Path) -> Path | None:
        for name in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
            f = cve_dir / name
            if f.exists():
                return f
        return None

    def _find_dockerfile(self, cve_dir: Path) -> Path | None:
        for f in cve_dir.rglob("Dockerfile"):
            return f
        return None

    def _find_launch_script(self, cve_dir: Path) -> Path | None:
        for f in sorted(cve_dir.glob("*.sh")):
            return f
        return None

    def _extract_compose_ports(self, compose_file: Path) -> list[int]:
        import yaml

        try:
            data = yaml.safe_load(compose_file.read_text(encoding="utf-8"))
        except Exception:
            return []
        if not isinstance(data, dict):
            return []

        ports = []
        services = data.get("services", {})
        for svc in services.values():
            for port_entry in svc.get("ports", []):
                port_str = str(port_entry)
                match = re.match(r'"?(\d+):\d+"?', port_str)
                if match:
                    ports.append(int(match.group(1)))
        return sorted(set(ports))

    def _infer_url_from_ports(self, ports: list[int]) -> str | None:
        if not ports:
            return None
        preferred = [80, 8080, 9080, 3000, 8000, 8443, 443]
        for p in preferred:
            if p in ports:
                return f"http://127.0.0.1:{p}"
        return f"http://127.0.0.1:{ports[0]}"

    async def launch(self, env: TargetEnvironment, timeout: int = 300) -> TargetEnvironment:
        if not env.supported:
            raise RuntimeError(
                f"{env.cve_id} is marked unsupported in the manifest"
                + (f": {env.note}" if env.note else "")
            )
        if env.launch_method == LaunchMethod.DOCKER_COMPOSE:
            return await self._launch_compose(env, timeout)
        elif env.launch_method == LaunchMethod.DOCKERFILE:
            return await self._launch_dockerfile(env, timeout)
        elif env.launch_method == LaunchMethod.IMAGE:
            return await self._launch_image(env, timeout)
        elif env.launch_method == LaunchMethod.SCRIPT:
            return await self._launch_script(env, timeout)
        else:
            raise RuntimeError(f"Cannot launch environment with method: {env.launch_method}")

    async def _launch_compose(self, env: TargetEnvironment, timeout: int) -> TargetEnvironment:
        logger.info("launching_compose", cve_id=env.cve_id, compose_file=env.compose_file)
        compose_path = Path(env.compose_file)
        build_timeout = max(timeout, env.build_timeout_s)
        proc = await asyncio.create_subprocess_exec(
            "docker", "compose", "-f", compose_path.name, "up", "-d", "--build",
            cwd=str(compose_path.parent),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=build_timeout)
        except asyncio.TimeoutError as exc:
            proc.kill()
            raise RuntimeError(
                f"docker compose up for {env.cve_id} timed out after {build_timeout}s "
                f"— raise build_timeout_s in the manifest for this heavy stack"
            ) from exc

        if proc.returncode != 0:
            raise RuntimeError(
                f"docker compose up failed for {env.cve_id}: {stderr.decode()[-600:]}"
            )

        await self._wait_healthy(env, timeout=env.startup_timeout_s)
        env.running = True
        logger.info("compose_launched", cve_id=env.cve_id, ports=env.ports)
        return env

    async def _launch_dockerfile(self, env: TargetEnvironment, timeout: int) -> TargetEnvironment:
        logger.info("launching_dockerfile", cve_id=env.cve_id)
        tag = f"pentest-{env.cve_id.lower()}"

        context = env.build_context or (
            str(Path(env.dockerfile_path).parent) if env.dockerfile_path else env.directory
        )
        build_cmd = ["docker", "build", "-t", tag]
        if env.dockerfile_path:
            build_cmd += ["-f", env.dockerfile_path]
        build_cmd.append(context)

        proc = await asyncio.create_subprocess_exec(
            *build_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            _, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=env.build_timeout_s
            )
        except asyncio.TimeoutError as exc:
            proc.kill()
            raise RuntimeError(
                f"docker build for {env.cve_id} timed out after "
                f"{env.build_timeout_s}s — raise build_timeout_s in the manifest "
                f"for this heavy build"
            ) from exc
        if proc.returncode != 0:
            raise RuntimeError(f"docker build failed for {env.cve_id}: {stderr.decode()[-500:]}")

        await self._docker_run(env, tag)
        await self._wait_healthy(env, timeout=env.startup_timeout_s)
        env.running = True
        logger.info("dockerfile_launched", cve_id=env.cve_id, port=env.host_port)
        return env

    async def _launch_image(self, env: TargetEnvironment, timeout: int) -> TargetEnvironment:
        logger.info("launching_image", cve_id=env.cve_id, image=env.image)
        if not env.image:
            raise RuntimeError(f"{env.cve_id}: method 'image' requires an image name")
        proc = await asyncio.create_subprocess_exec(
            "docker", "pull", env.image,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(proc.communicate(), timeout=timeout)

        await self._docker_run(env, env.image)
        await self._wait_healthy(env, timeout=env.startup_timeout_s)
        env.running = True
        logger.info("image_launched", cve_id=env.cve_id, port=env.host_port)
        return env

    async def _docker_run(self, env: TargetEnvironment, image_or_tag: str) -> None:
        container_name = f"pentest-{env.cve_id.lower()}"
        host = env.host_port or 8080
        container = env.container_port or host

        rm = await asyncio.create_subprocess_exec(
            "docker", "rm", "-f", container_name,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(rm.communicate(), timeout=30)

        cmd = ["docker", "run", "-d", "--name", container_name,
               "-p", f"{host}:{container}"]
        for k, v in env.env.items():
            cmd += ["-e", f"{k}={v}"]
        cmd += list(env.run_args)
        cmd.append(image_or_tag)

        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
        if proc.returncode != 0:
            raise RuntimeError(f"docker run failed for {env.cve_id}: {stderr.decode()[-500:]}")

        env.host_port = host
        env.ports = [host]
        env.target_url = f"http://127.0.0.1:{host}"

    async def _launch_script(self, env: TargetEnvironment, timeout: int) -> TargetEnvironment:
        logger.info("launching_script", cve_id=env.cve_id, script=env.script_path)
        proc = await asyncio.create_subprocess_exec(
            "bash", env.script_path,
            cwd=env.directory,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        if proc.returncode != 0:
            raise RuntimeError(f"Launch script failed for {env.cve_id}: {stderr.decode()}")

        env.running = True
        logger.info("script_launched", cve_id=env.cve_id)
        return env

    def _health_url(self, env: TargetEnvironment) -> str | None:
        if not env.target_url:
            return None
        path = env.health_path or "/"
        if not path.startswith("/"):
            path = "/" + path
        return env.target_url.rstrip("/") + path

    async def _wait_healthy(self, env: TargetEnvironment, timeout: int = 60) -> None:
        url = self._health_url(env)
        if not url:
            return
        deadline = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < deadline:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
                    "--connect-timeout", "3", "--max-time", "5", url,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
                code = stdout.decode().strip()
                if code and code != "000":
                    logger.info("target_healthy", cve_id=env.cve_id, http_code=code, url=url)
                    return
            except (asyncio.TimeoutError, OSError):
                pass
            await asyncio.sleep(3)
        raise TimeoutError(f"Target {url} not reachable after {timeout}s")

    async def teardown(self, env: TargetEnvironment) -> None:
        if not env.running:
            return

        if env.launch_method == LaunchMethod.DOCKER_COMPOSE and env.compose_file:
            logger.info("tearing_down_compose", cve_id=env.cve_id)
            compose_path = Path(env.compose_file)
            proc = await asyncio.create_subprocess_exec(
                "docker", "compose", "-f", compose_path.name, "down", "-v",
                cwd=str(compose_path.parent),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=60)
        elif env.launch_method in (LaunchMethod.DOCKERFILE, LaunchMethod.IMAGE):
            container_name = f"pentest-{env.cve_id.lower()}"
            logger.info("tearing_down_container", cve_id=env.cve_id, container=container_name)
            proc = await asyncio.create_subprocess_exec(
                "docker", "rm", "-f", container_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=30)

        env.running = False
        logger.info("environment_torn_down", cve_id=env.cve_id)

    async def is_reachable(self, env: TargetEnvironment) -> bool:
        url = self._health_url(env)
        if not url:
            return False
        try:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
                "--connect-timeout", "5", "--max-time", "10", url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            code = stdout.decode().strip()
            return bool(code and code != "000")
        except (asyncio.TimeoutError, OSError):
            return False
