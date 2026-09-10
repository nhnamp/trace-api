from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

import structlog
from pydantic import BaseModel

from src.models.session import SessionState

logger = structlog.get_logger(__name__)

_FAILED_TERMINAL_STATES = frozenset({"FAILED"})


class PlanningMetrics(BaseModel):
    recon_finding_count: int = 0
    recon_iterations: int = 0
    graph_node_count: int = 0
    graph_edge_count: int = 0
    rag_results_count: int = 0
    plan_step_count: int = 0
    plan_revision_count: int = 0
    plan_approved_first_attempt: bool = False
    vulnerability_hypothesis_type: str = ""
    vulnerability_hypothesis_confidence: str = ""


class ExploitationMetrics(BaseModel):
    total_steps_executed: int = 0
    steps_succeeded: int = 0
    steps_failed: int = 0
    steps_skipped: int = 0
    fallbacks_used: int = 0
    evidence_items: int = 0
    total_execution_ms: int = 0


class ReportingMetrics(BaseModel):
    report_generated: bool = False
    report_path: str = ""


class LLMUsageMetrics(BaseModel):
    total_calls: int = 0
    total_prompt_tokens: int = 0
    total_completion_tokens: int = 0
    total_tokens: int = 0


class RunMetrics(BaseModel):
    run_id: str = ""
    cve_id: str = ""
    target_url: str = ""
    model: str = ""
    config_label: str = ""
    final_state: str = ""
    wall_clock_seconds: float = 0.0
    started_at: str = ""
    completed_at: str = ""
    planning: PlanningMetrics = PlanningMetrics()
    exploitation: ExploitationMetrics = ExploitationMetrics()
    reporting: ReportingMetrics = ReportingMetrics()
    llm_usage: LLMUsageMetrics = LLMUsageMetrics()
    failure_count: int = 0
    error: str | None = None


class MetricsCollector:
    def __init__(self) -> None:
        self._start_time: float | None = None
        self._start_timestamp: str = ""

    def start_timer(self) -> None:
        self._start_time = time.monotonic()
        self._start_timestamp = datetime.now(timezone.utc).isoformat()

    def collect(
        self,
        session: SessionState,
        *,
        run_id: str = "",
        config_label: str = "",
        model: str = "",
        llm_log_dir: str | Path = "sessions",
    ) -> RunMetrics:
        elapsed = 0.0
        if self._start_time is not None:
            elapsed = time.monotonic() - self._start_time

        planning = self._collect_planning(session)
        exploitation = self._collect_exploitation(session)
        reporting = self._collect_reporting(session)
        llm_usage = self._collect_llm_usage(session, llm_log_dir)

        return RunMetrics(
            run_id=run_id,
            cve_id=session.target.cve_id or "",
            target_url=session.target.url,
            model=model,
            config_label=config_label,
            final_state=session.fsm_state.value,
            wall_clock_seconds=round(elapsed, 2),
            started_at=self._start_timestamp,
            completed_at=datetime.now(timezone.utc).isoformat(),
            planning=planning,
            exploitation=exploitation,
            reporting=reporting,
            llm_usage=llm_usage,
            failure_count=len(session.failure_history),
            error=(
                session.failure_history[-1].error
                if (session.fsm_state.value in _FAILED_TERMINAL_STATES
                    and session.failure_history)
                else None
            ),
        )

    def _collect_planning(self, session: SessionState) -> PlanningMetrics:
        metrics = PlanningMetrics(
            recon_finding_count=len(session.recon_results),
            rag_results_count=len(session.rag_context),
            plan_revision_count=session.plan_revision_count,
            plan_approved_first_attempt=session.plan_revision_count == 0 and session.attack_plan is not None,
        )

        if session.api_graph_data:
            metrics.graph_node_count = len(session.api_graph_data.get("nodes", []))
            metrics.graph_edge_count = len(session.api_graph_data.get("edges", []))

        if session.attack_plan:
            metrics.plan_step_count = len(session.attack_plan.steps)
            if session.attack_plan.vulnerability_hypothesis:
                metrics.vulnerability_hypothesis_type = session.attack_plan.vulnerability_hypothesis.type
                metrics.vulnerability_hypothesis_confidence = session.attack_plan.vulnerability_hypothesis.confidence

        return metrics

    def _collect_exploitation(self, session: SessionState) -> ExploitationMetrics:
        if not session.exploit_trace:
            return ExploitationMetrics()

        succeeded = sum(1 for s in session.exploit_trace if s.status.value == "SUCCESS")
        failed = sum(1 for s in session.exploit_trace if s.status.value == "FAILED")
        skipped = sum(1 for s in session.exploit_trace if s.status.value == "SKIPPED")
        fallbacks = sum(1 for s in session.exploit_trace if s.status.value == "FALLBACK_USED")
        evidence = sum(1 for s in session.exploit_trace if s.is_evidence)
        total_ms = sum(s.duration_ms for s in session.exploit_trace)

        return ExploitationMetrics(
            total_steps_executed=len(session.exploit_trace),
            steps_succeeded=succeeded,
            steps_failed=failed,
            steps_skipped=skipped,
            fallbacks_used=fallbacks,
            evidence_items=evidence,
            total_execution_ms=total_ms,
        )

    def _collect_reporting(self, session: SessionState) -> ReportingMetrics:
        return ReportingMetrics(
            report_generated=session.report_path is not None,
            report_path=session.report_path or "",
        )

    def _collect_llm_usage(self, session: SessionState, llm_log_dir: str | Path) -> LLMUsageMetrics:
        llm_log_dir = Path(llm_log_dir)
        log_path = llm_log_dir / f"sess-{session.session_id}" / "llm_calls.jsonl"
        if not log_path.exists():
            return LLMUsageMetrics()

        total_calls = 0
        prompt_tokens = 0
        completion_tokens = 0
        for line in log_path.read_text(encoding="utf-8").strip().splitlines():
            if not line:
                continue
            try:
                record = json.loads(line)
                usage = record.get("usage", {}) or {}
                total_calls += usage.get("api_calls") or 1
                prompt_tokens += usage.get("prompt_tokens") or 0
                completion_tokens += usage.get("completion_tokens") or 0
            except json.JSONDecodeError:
                continue

        return LLMUsageMetrics(
            total_calls=total_calls,
            total_prompt_tokens=prompt_tokens,
            total_completion_tokens=completion_tokens,
            total_tokens=prompt_tokens + completion_tokens,
        )

    @staticmethod
    def save_metrics(metrics: RunMetrics, output_path: str | Path) -> Path:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            metrics.model_dump_json(indent=2),
            encoding="utf-8",
        )
        logger.info("metrics_saved", path=str(path), run_id=metrics.run_id)
        return path

    @staticmethod
    def load_metrics(path: str | Path) -> RunMetrics:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return RunMetrics(**data)

    @staticmethod
    def save_batch_metrics(metrics_list: list[RunMetrics], output_path: str | Path) -> Path:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = [m.model_dump() for m in metrics_list]
        path.write_text(
            json.dumps(data, indent=2, default=str),
            encoding="utf-8",
        )
        logger.info("batch_metrics_saved", path=str(path), count=len(metrics_list))
        return path

    @staticmethod
    def load_batch_metrics(path: str | Path) -> list[RunMetrics]:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return [RunMetrics(**entry) for entry in data]
