from __future__ import annotations

from pathlib import Path

import structlog
from pydantic import BaseModel

from src.evaluation.metrics import MetricsCollector, RunMetrics

logger = structlog.get_logger(__name__)

_SKIPPED_STATES = {"SKIPPED"}
_ERRORED_STATES = {"ERROR", "FAILED"}


class AggregateGroup(BaseModel):
    key: str
    runs: int = 0
    completed: int = 0
    skipped: int = 0
    errored: int = 0
    with_evidence: int = 0
    total_evidence_items: int = 0
    total_wall_clock_seconds: float = 0.0
    total_llm_calls: int = 0
    total_tokens: int = 0


class AggregateResult(BaseModel):
    name: str
    source_files: list[str] = []
    total_runs: int = 0
    duplicate_run_ids: list[str] = []
    by_model: list[AggregateGroup] = []
    overall: AggregateGroup = AggregateGroup(key="(all)")
    metrics: list[RunMetrics] = []


def _roll_up(key: str, rows: list[RunMetrics]) -> AggregateGroup:
    return AggregateGroup(
        key=key,
        runs=len(rows),
        completed=sum(1 for m in rows if m.final_state == "COMPLETED"),
        skipped=sum(1 for m in rows if m.final_state in _SKIPPED_STATES),
        errored=sum(1 for m in rows if m.final_state in _ERRORED_STATES),
        with_evidence=sum(1 for m in rows if m.exploitation.evidence_items > 0),
        total_evidence_items=sum(m.exploitation.evidence_items for m in rows),
        total_wall_clock_seconds=round(sum(m.wall_clock_seconds for m in rows), 1),
        total_llm_calls=sum(m.llm_usage.total_calls for m in rows),
        total_tokens=sum(m.llm_usage.total_tokens for m in rows),
    )


def aggregate_batches(files: list[str | Path], name: str = "aggregate") -> AggregateResult:
    rows: list[RunMetrics] = []
    seen: set[str] = set()
    duplicates: list[str] = []
    for f in files:
        for m in MetricsCollector.load_batch_metrics(f):
            if m.run_id and m.run_id in seen:
                duplicates.append(m.run_id)
                continue
            if m.run_id:
                seen.add(m.run_id)
            rows.append(m)

    rows.sort(key=lambda m: (m.model, m.cve_id))
    models = sorted({m.model for m in rows})
    by_model = [_roll_up(mo, [m for m in rows if m.model == mo]) for mo in models]

    return AggregateResult(
        name=name,
        source_files=[str(f) for f in files],
        total_runs=len(rows),
        duplicate_run_ids=duplicates,
        by_model=by_model,
        overall=_roll_up("(all)", rows),
        metrics=rows,
    )


def render_aggregate_report(agg: AggregateResult) -> str:
    lines = [
        f"# Aggregate Report: {agg.name}",
        "",
        f"**Source files ({len(agg.source_files)}):**",
        "",
    ]
    lines += [f"- `{f}`" for f in agg.source_files]
    lines += ["", f"**Total runs:** {agg.total_runs}", ""]
    if agg.duplicate_run_ids:
        lines += [
            f"> Skipped {len(agg.duplicate_run_ids)} duplicate run_id(s) while merging: "
            f"{', '.join(agg.duplicate_run_ids)}.",
            "",
        ]
    lines += [
        "> OPERATIONAL only — raw counts merged across waves. It makes NO judgement about "
        "whether a CVE was exploited; that is assessed externally from each run's evidence, "
        "report and logs.",
        "",
        "## Summary by Model",
        "",
        "| Model | Runs | Completed | Skipped | Errored | With Evidence | Σ Evidence | Σ Time (s) | Σ LLM Calls | Σ Tokens |",
        "|-------|------|-----------|---------|---------|---------------|------------|------------|-------------|----------|",
    ]
    for g in [*agg.by_model, agg.overall]:
        lines.append(
            f"| {g.key} | {g.runs} | {g.completed} | {g.skipped} | {g.errored} | "
            f"{g.with_evidence} | {g.total_evidence_items} | {g.total_wall_clock_seconds:.1f} | "
            f"{g.total_llm_calls} | {g.total_tokens} |"
        )

    lines += [
        "",
        "## Per-CVE Results",
        "",
        "| CVE | Model | State | Time (s) | Recon | Plan Steps | Evidence Flagged | LLM Calls |",
        "|-----|-------|-------|----------|-------|------------|------------------|-----------|",
    ]
    for m in agg.metrics:
        lines.append(
            f"| {m.cve_id} | {m.model} | {m.final_state} | {m.wall_clock_seconds:.1f} | "
            f"{m.planning.recon_finding_count} | {m.planning.plan_step_count} | "
            f"{m.exploitation.evidence_items} | {m.llm_usage.total_calls} |"
        )
    lines.append("")
    return "\n".join(lines)


def save_aggregate(agg: AggregateResult, output_dir: str | Path) -> tuple[Path, Path]:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    metrics_path = output_dir / f"aggregate-{agg.name}_metrics.json"
    MetricsCollector.save_batch_metrics(agg.metrics, metrics_path)

    report_path = output_dir / f"aggregate-{agg.name}_report.md"
    report_path.write_text(render_aggregate_report(agg), encoding="utf-8")

    logger.info(
        "aggregate_saved", name=agg.name, runs=agg.total_runs,
        metrics=str(metrics_path), report=str(report_path),
    )
    return metrics_path, report_path
