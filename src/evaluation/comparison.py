from __future__ import annotations

import json
import uuid
from pathlib import Path

import structlog
from pydantic import BaseModel

from src.config.settings import SystemConfig
from src.evaluation.batch_runner import BatchResult, BatchRunner

logger = structlog.get_logger(__name__)


class ConfigVariant(BaseModel):
    label: str
    model: str | None = None
    provider: str | None = None
    temperature: float | None = None
    max_recon_iterations: int | None = None
    max_replans: int | None = None


class ComparisonResult(BaseModel):
    comparison_id: str
    cve_ids: list[str]
    variants: list[str]
    results: dict[str, BatchResult] = {}

    def get_summary_table(self) -> list[dict]:
        rows = []
        for label, batch in self.results.items():
            scored = [m for m in batch.metrics if m.final_state not in ("SKIPPED", "ERROR")]
            n = len(scored)
            avg_time = sum(m.wall_clock_seconds for m in scored) / n if n else 0.0
            avg_llm_calls = sum(m.llm_usage.total_calls for m in scored) / n if n else 0.0
            avg_tokens = sum(m.llm_usage.total_tokens for m in scored) / n if n else 0.0
            avg_evidence = sum(m.exploitation.evidence_items for m in scored) / n if n else 0.0

            rows.append({
                "variant": label,
                "total_runs": batch.total_runs,
                "completed": batch.completed_runs,
                "skipped": batch.skipped_runs,
                "avg_evidence": round(avg_evidence, 1),
                "avg_time_s": round(avg_time, 1),
                "avg_llm_calls": round(avg_llm_calls, 1),
                "avg_tokens": round(avg_tokens),
            })
        return rows


class ComparisonFramework:
    def __init__(
        self,
        base_config: SystemConfig,
        dataset_dir: str | Path,
        *,
        auto_launch: bool = True,
        auto_teardown: bool = True,
    ) -> None:
        self.base_config = base_config
        self.dataset_dir = Path(dataset_dir)
        self.auto_launch = auto_launch
        self.auto_teardown = auto_teardown

    def _apply_variant(self, base: SystemConfig, variant: ConfigVariant) -> SystemConfig:
        config = base.model_copy(deep=True)

        if variant.model is not None:
            config.llm.model = variant.model
            for name in config.llm._AGENT_FIELDS:
                getattr(config.llm, name).model = variant.model

        if variant.provider is not None:
            config.llm.provider = variant.provider
            for name in config.llm._AGENT_FIELDS:
                getattr(config.llm, name).provider = variant.provider

        if variant.temperature is not None:
            config.llm.planning.temperature = variant.temperature
            config.llm.exploiting.temperature = variant.temperature

        if variant.max_recon_iterations is not None:
            config.recon.max_iterations = variant.max_recon_iterations

        if variant.max_replans is not None:
            config.orchestrator.max_replans = variant.max_replans

        return config

    async def run_comparison(
        self,
        cve_ids: list[str],
        variants: list[ConfigVariant],
    ) -> ComparisonResult:
        comparison_id = f"cmp-{uuid.uuid4().hex[:8]}"
        logger.info(
            "comparison_start",
            comparison_id=comparison_id,
            cve_count=len(cve_ids),
            variant_count=len(variants),
        )

        result = ComparisonResult(
            comparison_id=comparison_id,
            cve_ids=cve_ids,
            variants=[v.label for v in variants],
        )

        for variant in variants:
            logger.info("comparison_variant_start", variant=variant.label)

            variant_config = self._apply_variant(self.base_config, variant)
            runner = BatchRunner(
                variant_config,
                self.dataset_dir,
                auto_launch=self.auto_launch,
                auto_teardown=self.auto_teardown,
                fresh_knowledge=True,
            )

            batch_result = await runner.run_batch(cve_ids, config_label=variant.label)
            result.results[variant.label] = batch_result

            logger.info(
                "comparison_variant_complete",
                variant=variant.label,
                completed=batch_result.completed_runs,
                skipped=batch_result.skipped_runs,
            )

        logger.info("comparison_complete", comparison_id=comparison_id)
        return result

    def save_comparison(self, result: ComparisonResult, output_dir: str | Path) -> Path:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        data_path = output_dir / f"{result.comparison_id}_data.json"
        serializable = {
            "comparison_id": result.comparison_id,
            "cve_ids": result.cve_ids,
            "variants": result.variants,
            "results": {
                label: batch.model_dump()
                for label, batch in result.results.items()
            },
        }
        data_path.write_text(
            json.dumps(serializable, indent=2, default=str),
            encoding="utf-8",
        )

        report_path = output_dir / f"{result.comparison_id}_report.md"
        report_path.write_text(
            self._generate_comparison_report(result),
            encoding="utf-8",
        )

        logger.info("comparison_saved", output_dir=str(output_dir))
        return output_dir

    def _generate_comparison_report(self, result: ComparisonResult) -> str:
        lines = [
            f"# Comparison Report: {result.comparison_id}",
            "",
            f"**CVEs Tested:** {', '.join(result.cve_ids)}",
            f"**Variants:** {len(result.variants)}",
            "",
            "## Summary",
            "",
            "> Operational metrics only — no exploitation success verdict. Compare "
            "variants on cost/behaviour (time, calls, tokens, evidence flagged); the "
            "actual exploitation outcome per CVE is judged externally from the "
            "evidence, per-CVE reports and logs.",
            "",
            "| Variant | Runs | Completed | Skipped | Avg Evidence | Avg Time (s) | Avg LLM Calls | Avg Tokens |",
            "|---------|------|-----------|---------|--------------|--------------|----------------|------------|",
        ]

        for row in result.get_summary_table():
            lines.append(
                f"| {row['variant']} | {row['total_runs']} | {row['completed']} | "
                f"{row['skipped']} | {row['avg_evidence']} | {row['avg_time_s']} | "
                f"{row['avg_llm_calls']} | {row['avg_tokens']} |"
            )

        for label, batch in result.results.items():
            lines.extend([
                "",
                f"## Variant: {label}",
                "",
                f"**Batch ID:** {batch.batch_id}",
                f"**Completed:** {batch.completed_runs} / {batch.attempted_runs} attempted",
                "",
                "| CVE | State | Time (s) | Recon | Plan Steps | Evidence Flagged | Tokens |",
                "|-----|-------|----------|-------|------------|------------------|--------|",
            ])

            for m in batch.metrics:
                lines.append(
                    f"| {m.cve_id} | {m.final_state} | {m.wall_clock_seconds:.1f} | "
                    f"{m.planning.recon_finding_count} | {m.planning.plan_step_count} | "
                    f"{m.exploitation.evidence_items} | {m.llm_usage.total_tokens} |"
                )

            errors = [m for m in batch.metrics if m.error]
            if errors:
                lines.extend(["", "### Errors", ""])
                for m in errors:
                    lines.append(f"- **{m.cve_id}**: {m.error}")

        lines.append("")
        return "\n".join(lines)
