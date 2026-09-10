from __future__ import annotations

import asyncio

import structlog

logger = structlog.get_logger(__name__)

DEFAULT_IMAGE = "trace-api-executor:latest"
DEFAULT_NETWORK = "host"


class SandboxError(Exception):
    pass


class DockerSandbox:
    def __init__(
        self,
        *,
        image: str = DEFAULT_IMAGE,
        container_name: str | None = None,
        network_mode: str = DEFAULT_NETWORK,
        extra_volumes: list[str] | None = None,
        extra_env: dict[str, str] | None = None,
    ):
        self.image = image
        self.container_name = container_name or "trace-api-sandbox"
        self.network_mode = network_mode
        self.extra_volumes = extra_volumes or []
        self.extra_env = extra_env or {}
        self._container_id: str | None = None
        self._running = False

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def container_id(self) -> str | None:
        return self._container_id

    async def start(self) -> str:
        if self._running and self._container_id:
            return self._container_id

        await self._remove_existing()

        cmd_parts = [
            "docker", "run", "-d",
            "--name", self.container_name,
            f"--network={self.network_mode}",
        ]
        for vol in self.extra_volumes:
            cmd_parts.extend(["-v", vol])
        for key, val in self.extra_env.items():
            cmd_parts.extend(["-e", f"{key}={val}"])
        cmd_parts.extend([self.image, "sleep", "infinity"])

        cmd = " ".join(cmd_parts)
        logger.info("sandbox_starting", image=self.image, name=self.container_name)

        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

        if proc.returncode != 0:
            err_msg = stderr.decode("utf-8", errors="replace").strip()
            raise SandboxError(f"Failed to start sandbox container: {err_msg}")

        self._container_id = stdout.decode("utf-8", errors="replace").strip()[:12]
        self._running = True

        logger.info(
            "sandbox_started",
            container_id=self._container_id,
            name=self.container_name,
        )
        return self._container_id

    async def execute(
        self,
        command: str,
        *,
        timeout: int = 60,
        workdir: str | None = None,
        env: dict[str, str] | None = None,
    ) -> tuple[int, str, str]:
        if not self._running:
            raise SandboxError("Sandbox container is not running — call start() first")

        exec_parts = ["docker", "exec"]
        if workdir:
            exec_parts.extend(["-w", workdir])
        if env:
            for key, val in env.items():
                exec_parts.extend(["-e", f"{key}={val}"])
        exec_parts.extend([self.container_name, "sh", "-c", command])

        full_cmd = exec_parts[0:3]
        if workdir:
            full_cmd.extend(["-w", workdir])
        if env:
            for key, val in env.items():
                full_cmd.extend(["-e", f"{key}={val}"])
        full_cmd.extend([self.container_name, "sh", "-c", command])

        cmd_str = " ".join(
            f"'{p}'" if " " in p or "'" in p else p
            for p in ["docker", "exec"]
            + (["-w", workdir] if workdir else [])
            + [f"-e {k}={v}" for k, v in (env or {}).items()]
            + [self.container_name, "sh", "-c", f"'{command}'"]
        )

        proc = await asyncio.create_subprocess_shell(
            cmd_str,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return -1, "", f"Command timed out after {timeout}s"

        exit_code = proc.returncode or 0
        stdout_str = stdout.decode("utf-8", errors="replace")
        stderr_str = stderr.decode("utf-8", errors="replace")
        return exit_code, stdout_str, stderr_str

    async def stop(self) -> None:
        if not self._running:
            return

        logger.info("sandbox_stopping", name=self.container_name)

        proc = await asyncio.create_subprocess_shell(
            f"docker rm -f {self.container_name}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()

        self._container_id = None
        self._running = False
        logger.info("sandbox_stopped", name=self.container_name)

    async def _remove_existing(self) -> None:
        proc = await asyncio.create_subprocess_shell(
            f"docker rm -f {self.container_name} 2>/dev/null",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()

    async def is_docker_available(self) -> bool:
        proc = await asyncio.create_subprocess_shell(
            "docker info >/dev/null 2>&1",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()
        return proc.returncode == 0

    async def image_exists(self) -> bool:
        proc = await asyncio.create_subprocess_shell(
            f"docker image inspect {self.image} >/dev/null 2>&1",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()
        return proc.returncode == 0
