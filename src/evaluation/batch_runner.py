from __future__ import annotations

import shutil
import tempfile
import time
import uuid
from collections.abc import Callable
from pathlib import Path

import structlog
from pydantic import BaseModel

from src.config.settings import SystemConfig
from src.evaluation.metrics import MetricsCollector, RunMetrics
from src.knowledge.knowledge_ingest import KnowledgeIngestor
from src.knowledge.rag_engine import RAGEngine
from src.models.target import TargetInfo
from src.orchestrator.orchestrator import Orchestrator
from src.targets.target_manager import TargetManager

logger = structlog.get_logger(__name__)


class ProgressUpdate(BaseModel):
    index: int
    total: int
    metrics: RunMetrics
    elapsed_seconds: float
    eta_seconds: float
    completed: int
    skipped: int


class BatchResult(BaseModel):
    batch_id: str
    config_label: str = ""
    total_runs: int = 0
    completed_runs: int = 0
    skipped_runs: int = 0
    metrics: list[RunMetrics] = []

    @property
    def attempted_runs(self) -> int:
        return self.total_runs - self.skipped_runs

    @property
    def completion_rate(self) -> float:
        if self.attempted_runs == 0:
            return 0.0
        return self.completed_runs / self.attempted_runs

    @property
    def skipped(self) -> list[RunMetrics]:
        return [m for m in self.metrics if m.final_state == "SKIPPED"]


class LaunchCheckResult(BaseModel):
    cve_id: str
    status: str
    target_url: str = ""
    duration_s: float = 0.0
    detail: str = ""

    @property
    def unsupported(self) -> bool:
        return self.status == "SKIPPED" and self.detail.startswith("unsupported")

    @property
    def is_failure(self) -> bool:
        return self.status == "UNREACHABLE" or (self.status == "SKIPPED" and not self.unsupported)


class BatchRunner:
    def __init__(
        self,
        config: SystemConfig,
        dataset_dir: str | Path,
        *,
        auto_launch: bool = True,
        auto_teardown: bool = True,
        ingest_knowledge: bool = True,
        fresh_knowledge: bool = False,
    ) -> None:
        self.config = config
        self.dataset_dir = Path(dataset_dir)
        self.target_manager = TargetManager(self.dataset_dir)
        self.auto_launch = auto_launch
        self.auto_teardown = auto_teardown
        self.ingest_knowledge = ingest_knowledge
        self.fresh_knowledge = fresh_knowledge

    def _reset_knowledge_base(self) -> None:
        for d in (self.config.knowledge.chroma_persist_dir,
                  self.config.knowledge.bm25_index_dir):
            shutil.rmtree(d, ignore_errors=True)
        logger.info("knowledge_base_reset",
                    chroma=self.config.knowledge.chroma_persist_dir,
                    bm25=self.config.knowledge.bm25_index_dir)

    async def run_single(
        self,
        cve_id: str,
        *,
        target_url: str | None = None,
        config_label: str = "",
    ) -> RunMetrics:
        run_id = f"run-{uuid.uuid4().hex[:8]}"
        model = self.config.llm.planning.model
        logger.info("batch_run_start", run_id=run_id, cve_id=cve_id, model=model)

        work_dir = tempfile.mkdtemp(prefix=f"pentest-{cve_id}-")
        env = None
        launched = False
        try:
            try:
                env = self.target_manager.get_environment(cve_id)

                if target_url:
                    env.target_url = target_url
                elif self.auto_launch and not await self.target_manager.is_reachable(env):
                    launched = True
                    env = await self.target_manager.launch(env)

                if not env.target_url:
                    raise RuntimeError("no target URL after launch")
                if not await self.target_manager.is_reachable(env):
                    raise RuntimeError(f"{env.target_url} not reachable")
            except Exception as bring_up_err:
                reason = str(bring_up_err)
                logger.warning("cve_skipped", cve_id=cve_id, reason=reason)
                return RunMetrics(
                    run_id=run_id,
                    cve_id=cve_id,
                    target_url=(env.target_url if env and env.target_url else ""),
                    model=model,
                    config_label=config_label,
                    final_state="SKIPPED",
                    error=reason,
                )

            rag_engine = RAGEngine(self.config.knowledge)
            if self.ingest_knowledge:
                ingestor = KnowledgeIngestor(rag_engine)
                ingestor.ingest_dataset(self.dataset_dir)

            orchestrator = Orchestrator(self.config, rag_engine=rag_engine, work_dir=work_dir)

            collector = MetricsCollector()
            collector.start_timer()

            target = TargetInfo(url=env.target_url, cve_id=cve_id)
            session = await orchestrator.run_session(target)

            metrics = collector.collect(
                session,
                run_id=run_id,
                config_label=config_label,
                model=model,
                llm_log_dir=self.config.logging.llm_log_dir,
            )

            logger.info(
                "batch_run_complete",
                run_id=run_id,
                cve_id=cve_id,
                final_state=metrics.final_state,
                evidence_items=metrics.exploitation.evidence_items,
                wall_clock=metrics.wall_clock_seconds,
            )
            return metrics

        except Exception as exc:
            logger.error("batch_run_error", run_id=run_id, cve_id=cve_id, error=str(exc))
            return RunMetrics(
                run_id=run_id,
                cve_id=cve_id,
                target_url=env.target_url if env and env.target_url else "",
                model=self.config.llm.planning.model,
                config_label=config_label,
                final_state="ERROR",
                error=str(exc),
            )
        finally:
            if env and self.auto_teardown and (launched or env.running):
                env.running = True
                try:
                    await self.target_manager.teardown(env)
                except Exception as teardown_err:
                    logger.warning("teardown_error", cve_id=cve_id, error=str(teardown_err))
            shutil.rmtree(work_dir, ignore_errors=True)

    async def run_batch(
        self,
        cve_ids: list[str],
        *,
        config_label: str = "",
        progress_callback: Callable[[ProgressUpdate], None] | None = None,
    ) -> BatchResult:
        batch_id = f"batch-{uuid.uuid4().hex[:8]}"
        logger.info("batch_start", batch_id=batch_id, cve_count=len(cve_ids))

        if self.fresh_knowledge:
            self._reset_knowledge_base()

        result = BatchResult(
            batch_id=batch_id,
            config_label=config_label,
            total_runs=len(cve_ids),
        )

        batch_start = time.monotonic()
        total = len(cve_ids)
        for index, cve_id in enumerate(cve_ids, start=1):
            metrics = await self.run_single(cve_id, config_label=config_label)
            result.metrics.append(metrics)

            if metrics.final_state == "SKIPPED":
                result.skipped_runs += 1
            elif metrics.final_state in ("COMPLETED", "FAILED"):
                result.completed_runs += 1

            if progress_callback is not None:
                elapsed = time.monotonic() - batch_start
                eta = (elapsed / index) * (total - index) if index else 0.0
                progress_callback(
                    ProgressUpdate(
                        index=index,
                        total=total,
                        metrics=metrics,
                        elapsed_seconds=elapsed,
                        eta_seconds=eta,
                        completed=result.completed_runs,
                        skipped=result.skipped_runs,
                    )
                )

        logger.info(
            "batch_complete",
            batch_id=batch_id,
            attempted=result.attempted_runs,
            completed=result.completed_runs,
            skipped=result.skipped_runs,
        )
        return result

    def all_cve_ids(self) -> list[str]:
        return sorted(
            d.name for d in self.dataset_dir.iterdir()
            if d.is_dir() and d.name.startswith("CVE-")
        )

    async def check_target(self, cve_id: str) -> LaunchCheckResult:
        start = time.monotonic()
        env = None
        launched = False
        try:
            try:
                env = self.target_manager.get_environment(cve_id)
                if not env.supported:
                    reason = env.note or "marked unsupported in the manifest"
                    return LaunchCheckResult(
                        cve_id=cve_id, status="SKIPPED", detail=f"unsupported: {reason}",
                    )

                already_up = await self.target_manager.is_reachable(env)
                if not already_up and self.auto_launch:
                    launched = True
                    env = await self.target_manager.launch(env)
                elif not already_up:
                    return LaunchCheckResult(
                        cve_id=cve_id, status="UNREACHABLE",
                        target_url=env.target_url or "",
                        duration_s=round(time.monotonic() - start, 1),
                        detail="not running (launch disabled)",
                    )

                reachable = await self.target_manager.is_reachable(env)
                return LaunchCheckResult(
                    cve_id=cve_id,
                    status="REACHABLE" if reachable else "UNREACHABLE",
                    target_url=env.target_url or "",
                    duration_s=round(time.monotonic() - start, 1),
                )
            except Exception as exc:
                return LaunchCheckResult(
                    cve_id=cve_id, status="SKIPPED",
                    target_url=(env.target_url if env and env.target_url else ""),
                    duration_s=round(time.monotonic() - start, 1),
                    detail=str(exc)[-300:],
                )
        finally:
            if env and self.auto_teardown and launched:
                env.running = True
                try:
                    await self.target_manager.teardown(env)
                except Exception as teardown_err:
                    logger.warning("teardown_error", cve_id=cve_id, error=str(teardown_err))

    async def check_all(self, cve_ids: list[str]) -> list[LaunchCheckResult]:
        results = []
        for cve_id in cve_ids:
            result = await self.check_target(cve_id)
            results.append(result)
            logger.info(
                "launch_check", cve_id=cve_id, status=result.status,
                duration_s=result.duration_s,
            )
        return results

    def save_results(self, result: BatchResult, output_dir: str | Path) -> Path:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        metrics_path = output_dir / f"{result.batch_id}_metrics.json"
        MetricsCollector.save_batch_metrics(result.metrics, metrics_path)

        summary_path = output_dir / f"{result.batch_id}_summary.json"
        summary_path.write_text(
            result.model_dump_json(indent=2, exclude={"metrics"}),
            encoding="utf-8",
        )

        report_path = output_dir / f"{result.batch_id}_report.md"
        report_path.write_text(
            self._generate_batch_report(result),
            encoding="utf-8",
        )

        logger.info("batch_results_saved", output_dir=str(output_dir), batch_id=result.batch_id)
        return output_dir

    def _generate_batch_report(self, result: BatchResult) -> str:
        lines = [
            f"# Batch Run Report: {result.batch_id}",
            "",
            f"**Config:** {result.config_label or 'default'}",
            f"**Total CVEs:** {result.total_runs}",
            f"**Attempted (launched OK):** {result.attempted_runs}",
            f"**Skipped (could not launch/reach):** {result.skipped_runs}",
            f"**Completed (reached end of pipeline):** {result.completed_runs}",
            f"**Completion Rate (of attempted):** {result.completion_rate:.1%}",
            "",
            "> This report is OPERATIONAL only — it records whether each run launched "
            "and finished, plus raw counts (recon findings, plan steps, evidence items "
            "flagged by the LLM, LLM calls). It intentionally makes NO judgement about "
            "whether a CVE was actually exploited; that assessment is done separately by "
            "reviewing each run's evidence, per-CVE report and logs.",
            "",
            "## Per-CVE Results",
            "",
            "| CVE | Model | State | Time (s) | Recon | Plan Steps | Evidence Flagged | LLM Calls |",
            "|-----|-------|-------|----------|-------|------------|------------------|-----------|",
        ]

        for m in result.metrics:
            lines.append(
                f"| {m.cve_id} | {m.model} | {m.final_state} | "
                f"{m.wall_clock_seconds:.1f} | "
                f"{m.planning.recon_finding_count} | {m.planning.plan_step_count} | "
                f"{m.exploitation.evidence_items} | {m.llm_usage.total_calls} |"
            )

        skipped = result.skipped
        if skipped:
            lines.extend([
                "", "## Skipped CVEs (could not launch / not reachable)", "",
                "These were not assessed — the environment could not be brought up.", "",
            ])
            for m in skipped:
                lines.append(f"- **{m.cve_id}**: {m.error}")

        errors = [m for m in result.metrics if m.error and m.final_state != "SKIPPED"]
        if errors:
            lines.extend(["", "## Pipeline Errors", ""])
            for m in errors:
                lines.append(f"- **{m.cve_id}** ({m.run_id}): {m.error}")

        lines.append("")
        return "\n".join(lines)
