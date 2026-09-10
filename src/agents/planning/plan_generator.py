from __future__ import annotations

import json
import uuid

import structlog

from pydantic import BaseModel

from src.graph.api_asset_graph import APIAssetGraph
from src.llm.client import LLMClient, LLMError
from src.llm.prompts.planning_plan import (
    FALLBACK_GEN_SYSTEM,
    PLAN_SYSTEM,
    STEPS_GEN_SYSTEM,
    fallback_generation_prompt,
    plan_generation_prompt,
    steps_generation_prompt,
)
from src.llm.token_budget import allocate_blocks, count_tokens, prompt_token_budget
from src.models.plan import AttackPlan, Fallback, PlanStep, ValidationResult
from src.models.recon import ReconFinding

logger = structlog.get_logger(__name__)

_MAX_FINDINGS = 20

_MAX_FALLBACKS_PER_STEP = 3


class _FallbackGenResult(BaseModel):
    fallbacks: dict[str, list[Fallback]] = {}


class _StepsGenResult(BaseModel):
    steps: list[PlanStep] = []


class PlanGenerator:
    def __init__(self, llm_client: LLMClient, generate_fallbacks: bool = True) -> None:
        self.llm_client = llm_client
        self.generate_fallbacks = generate_fallbacks

    async def generate_plan(
        self,
        target_url: str,
        cve_id: str | None,
        graph: APIAssetGraph,
        findings: list[ReconFinding],
        rag_context: list[dict],
        validation_feedback: ValidationResult | None = None,
        previous_plan: AttackPlan | None = None,
    ) -> AttackPlan:
        findings_summary = self._summarize_findings(findings)
        rag_text = self._format_rag_context(rag_context)

        feedback_text = None
        previous_plan_summary = None
        if validation_feedback and not validation_feedback.is_valid:
            issues = validation_feedback.structural_issues + validation_feedback.semantic_issues
            feedback_text = "\n".join(f"- {issue}" for issue in issues)
            if validation_feedback.suggestions:
                feedback_text += "\nSuggestions:\n" + "\n".join(
                    f"- {s}" for s in validation_feedback.suggestions
                )
            if previous_plan is not None:
                previous_plan_summary = self._summarize_previous_plan(previous_plan)

        graph_summary = graph.summary()
        budget = prompt_token_budget(
            self.llm_client.config.context_window,
            self.llm_client.config.max_tokens,
        )
        skeleton = plan_generation_prompt(
            target_url=target_url,
            cve_id=cve_id,
            graph_summary="",
            findings_summary="",
            rag_context="",
            validation_feedback=feedback_text,
            previous_plan_summary="" if previous_plan_summary else None,
        )
        base_tokens = count_tokens(PLAN_SYSTEM) + count_tokens(skeleton)
        findings_summary, graph_summary, prev_block, rag_text = allocate_blocks(
            [findings_summary, graph_summary, previous_plan_summary or "", rag_text],
            max(0, budget - base_tokens),
        )
        previous_plan_summary = prev_block or None

        prompt = plan_generation_prompt(
            target_url=target_url,
            cve_id=cve_id,
            graph_summary=graph_summary,
            findings_summary=findings_summary,
            rag_context=rag_text,
            validation_feedback=feedback_text,
            previous_plan_summary=previous_plan_summary,
        )

        messages = [
            {"role": "system", "content": PLAN_SYSTEM},
            {"role": "user", "content": prompt},
        ]

        plan = await self.llm_client.generate_json(
            messages, AttackPlan, purpose="plan_generation"
        )

        if not plan.plan_id:
            plan.plan_id = f"plan-{uuid.uuid4().hex[:8]}"

        if not plan.steps:
            await self._generate_steps(
                plan, target_url, cve_id, graph_summary, findings_summary, rag_text,
            )

        await self._generate_fallbacks(plan)

        logger.info(
            "plan_generated",
            plan_id=plan.plan_id,
            steps=len(plan.steps),
            fallbacks=sum(len(s.fallbacks) for s in plan.steps),
            hypothesis=plan.vulnerability_hypothesis.type,
            confidence=plan.vulnerability_hypothesis.confidence,
        )
        return plan

    async def _generate_steps(
        self,
        plan: AttackPlan,
        target_url: str,
        cve_id: str | None,
        graph_summary: str,
        findings_summary: str,
        rag_text: str,
    ) -> None:
        hyp = plan.vulnerability_hypothesis
        prompt = steps_generation_prompt(
            target_url=target_url,
            cve_id=cve_id,
            vuln_type=hyp.type,
            vuln_description=hyp.description,
            graph_summary=graph_summary,
            findings_summary=findings_summary,
            rag_context=rag_text,
        )
        messages = [
            {"role": "system", "content": STEPS_GEN_SYSTEM},
            {"role": "user", "content": prompt},
        ]
        try:
            result = await self.llm_client.generate_json(
                messages, _StepsGenResult, purpose="steps_generation"
            )
        except LLMError as exc:
            logger.warning("steps_generation_failed", plan_id=plan.plan_id, error=str(exc))
            return

        steps = [s for s in result.steps if s.command]
        if steps:
            plan.steps = steps
            logger.info("steps_generated_separately", plan_id=plan.plan_id, steps=len(steps))
        else:
            logger.warning("steps_generation_empty", plan_id=plan.plan_id)

    async def _generate_fallbacks(self, plan: AttackPlan) -> None:
        if not self.generate_fallbacks:
            return
        critical = [s for s in plan.steps if s.is_critical and s.command and s.step_id]
        if not critical:
            return

        steps_brief = "\n".join(
            f"- {s.step_id}: {s.description} | command: {s.command} "
            f"| proves: {s.success_criteria or '(unspecified)'}"
            for s in critical
        )
        messages = [
            {"role": "system", "content": FALLBACK_GEN_SYSTEM},
            {
                "role": "user",
                "content": fallback_generation_prompt(steps_brief, _MAX_FALLBACKS_PER_STEP),
            },
        ]
        try:
            result = await self.llm_client.generate_json(
                messages, _FallbackGenResult, purpose="fallback_generation"
            )
        except LLMError as exc:
            logger.warning("fallback_generation_failed", error=str(exc))
            return

        by_id = {s.step_id: s for s in plan.steps}
        for step_id, fbs in result.fallbacks.items():
            step = by_id.get(step_id)
            if step is not None and fbs:
                step.fallbacks = [fb for fb in fbs if fb.command][:_MAX_FALLBACKS_PER_STEP]

    @staticmethod
    def _summarize_previous_plan(plan: AttackPlan) -> str:
        lines = []
        for step in plan.steps:
            lines.append(f"[{step.step_id}] {step.description}")
            lines.append(f"    command: {step.command}")
            if step.success_criteria:
                lines.append(f"    success_criteria: {step.success_criteria}")
        return "\n".join(lines) if lines else "(previous plan had no steps)"

    def _summarize_findings(self, findings: list[ReconFinding]) -> str:
        if not findings:
            return "No reconnaissance findings."
        lines = []
        for f in findings[-_MAX_FINDINGS:]:
            lines.append(
                f"[{f.finding_id}] {f.finding_type}: {json.dumps(f.data)}"
            )
        return "\n".join(lines)

    def _format_rag_context(self, rag_context: list[dict]) -> str:
        if not rag_context:
            return ""
        parts = []
        for r in rag_context:
            content = r.get("content", "")
            if content:
                parts.append(content)
        return "\n\n---\n\n".join(parts)
