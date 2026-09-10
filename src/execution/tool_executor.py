from __future__ import annotations

import asyncio
import os
import signal
import time

import structlog

from src.config.settings import ExecutionConfig

logger = structlog.get_logger(__name__)


class ExecutionResult:
    def __init__(
        self,
        *,
        command: str,
        exit_code: int,
        stdout: str,
        stderr: str,
        timed_out: bool,
        truncated: bool,
        duration_ms: int,
    ):
        self.command = command
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.timed_out = timed_out
        self.truncated = truncated
        self.duration_ms = duration_ms

    @property
    def success(self) -> bool:
        return self.exit_code == 0 and not self.timed_out

    def to_dict(self) -> dict:
        return {
            "command": self.command,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "timed_out": self.timed_out,
            "truncated": self.truncated,
            "duration_ms": self.duration_ms,
        }


class ToolExecutor:
    def __init__(
        self,
        config: ExecutionConfig,
        sandbox: object | None = None,
        work_dir: str | None = None,
    ):
        self.config = config
        self._sandbox = sandbox
        self.work_dir = work_dir

    def _truncate(self, output: str) -> tuple[str, bool]:
        encoded = output.encode("utf-8", errors="replace")
        if len(encoded) <= self.config.max_output_bytes:
            return output, False
        truncated_bytes = encoded[: self.config.max_output_bytes]
        truncated_str = truncated_bytes.decode("utf-8", errors="replace")
        return truncated_str + "\n... [output truncated]", True

    async def execute(
        self,
        command: str,
        *,
        timeout: int | None = None,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
    ) -> ExecutionResult:
        cwd = cwd or self.work_dir
        if self.config.mode == "docker" and self._sandbox is not None:
            return await self._execute_docker(command, timeout=timeout, cwd=cwd, env=env)
        return await self._execute_host(command, timeout=timeout, cwd=cwd, env=env)

    async def _execute_docker(
        self,
        command: str,
        *,
        timeout: int | None = None,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
    ) -> ExecutionResult:
        from src.execution.sandbox import DockerSandbox

        sandbox: DockerSandbox = self._sandbox  # type: ignore[assignment]
        effective_timeout = min(
            timeout or self.config.timeout_seconds,
            self.config.max_timeout_seconds,
        )

        logger.info(
            "executing_command_docker",
            command=command,
            timeout=effective_timeout,
            container=sandbox.container_name,
        )

        start = time.monotonic()
        try:
            exit_code, stdout_str, stderr_str = await sandbox.execute(
                command, timeout=effective_timeout, workdir=cwd, env=env,
            )
        except Exception as exc:
            duration_ms = int((time.monotonic() - start) * 1000)
            logger.error("docker_exec_error", command=command, error=str(exc))
            return ExecutionResult(
                command=command,
                exit_code=-1,
                stdout="",
                stderr=f"Docker execution error: {exc}",
                timed_out=False,
                truncated=False,
                duration_ms=duration_ms,
            )

        duration_ms = int((time.monotonic() - start) * 1000)
        timed_out = exit_code == -1 and "timed out" in stderr_str

        stdout_str, stdout_truncated = self._truncate(stdout_str)
        stderr_str, stderr_truncated = self._truncate(stderr_str)
        truncated = stdout_truncated or stderr_truncated

        result = ExecutionResult(
            command=command,
            exit_code=exit_code,
            stdout=stdout_str,
            stderr=stderr_str,
            timed_out=timed_out,
            truncated=truncated,
            duration_ms=duration_ms,
        )

        logger.info(
            "command_complete_docker",
            command=command,
            exit_code=result.exit_code,
            duration_ms=duration_ms,
            truncated=truncated,
        )
        return result

    async def _execute_host(
        self,
        command: str,
        *,
        timeout: int | None = None,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
    ) -> ExecutionResult:
        effective_timeout = min(
            timeout or self.config.timeout_seconds,
            self.config.max_timeout_seconds,
        )

        logger.info(
            "executing_command",
            command=command,
            timeout=effective_timeout,
            cwd=cwd,
        )

        if cwd and env is None:
            env = {**os.environ, "TMPDIR": cwd, "TMP": cwd, "TEMP": cwd}

        start = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
                env=env,
                start_new_session=True,
            )
            try:
                raw_stdout, raw_stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=effective_timeout,
                )
            except asyncio.TimeoutError:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except OSError:
                    proc.kill()
                await proc.communicate()
                duration_ms = int((time.monotonic() - start) * 1000)
                logger.warning(
                    "command_timed_out",
                    command=command,
                    timeout=effective_timeout,
                    duration_ms=duration_ms,
                )
                return ExecutionResult(
                    command=command,
                    exit_code=-1,
                    stdout="",
                    stderr=f"Process timed out after {effective_timeout}s",
                    timed_out=True,
                    truncated=False,
                    duration_ms=duration_ms,
                )
        except OSError as exc:
            duration_ms = int((time.monotonic() - start) * 1000)
            logger.error("command_os_error", command=command, error=str(exc))
            return ExecutionResult(
                command=command,
                exit_code=-1,
                stdout="",
                stderr=f"OS error: {exc}",
                timed_out=False,
                truncated=False,
                duration_ms=duration_ms,
            )

        duration_ms = int((time.monotonic() - start) * 1000)

        stdout_str = raw_stdout.decode("utf-8", errors="replace")
        stderr_str = raw_stderr.decode("utf-8", errors="replace")

        stdout_str, stdout_truncated = self._truncate(stdout_str)
        stderr_str, stderr_truncated = self._truncate(stderr_str)
        truncated = stdout_truncated or stderr_truncated

        result = ExecutionResult(
            command=command,
            exit_code=proc.returncode or 0,
            stdout=stdout_str,
            stderr=stderr_str,
            timed_out=False,
            truncated=truncated,
            duration_ms=duration_ms,
        )

        logger.info(
            "command_complete",
            command=command,
            exit_code=result.exit_code,
            duration_ms=duration_ms,
            truncated=truncated,
        )
        return result
