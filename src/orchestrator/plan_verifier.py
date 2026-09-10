from __future__ import annotations

import json
import uuid

import structlog
from pydantic import BaseModel

from src.graph.api_asset_graph import APIAssetGraph
from src.llm.client import LLMClient
from src.llm.prompts.verifier import VERIFIER_SYSTEM, semantic_verification_prompt
from src.llm.token_budget import allocate_blocks, count_tokens, prompt_token_budget
from src.models.plan import AttackPlan, ValidationResult
from src.models.recon import ReconFinding

logger = structlog.get_logger(__name__)


class SemanticVerdict(BaseModel):
    is_valid: bool = False
    semantic_issues: list[str] = []
    suggestions: list[str] = []
    verdict: str = ""
    rejection_reason: str | None = None


class PlanVerifier:
    def __init__(self, llm_client: LLMClient) -> None:
        self.llm_client = llm_client

    async def verify(
        self,
        plan: AttackPlan,
        graph: APIAssetGraph,
        findings: list[ReconFinding],
        rag_context: list[dict],
    ) -> ValidationResult:
        plan = self._auto_repair(plan)
        structural_issues = self._structural_check(plan)

        if structural_issues:
            logger.info(
                "plan_structural_check_failed",
                plan_id=plan.plan_id,
                issues=len(structural_issues),
            )
            return ValidationResult(
                is_valid=False,
                structural_issues=structural_issues,
                rejection_reason="plan_quality",
            )

        semantic_result = await self._semantic_check(plan, graph, findings, rag_context)

        result = ValidationResult(
            is_valid=semantic_result.is_valid,
            structural_issues=[],
            semantic_issues=semantic_result.semantic_issues,
            suggestions=semantic_result.suggestions,
            rejection_reason=None if semantic_result.is_valid else semantic_result.rejection_reason,
        )

        logger.info(
            "plan_verification_complete",
            plan_id=plan.plan_id,
            is_valid=result.is_valid,
            structural_issues=len(result.structural_issues),
            semantic_issues=len(result.semantic_issues),
        )
        return result

    def _auto_repair(self, plan: AttackPlan) -> AttackPlan:
        if not plan.plan_id:
            plan.plan_id = f"plan-{uuid.uuid4().hex[:8]}"

        used_ids = {s.step_id for s in plan.steps if s.step_id}
        for i, step in enumerate(plan.steps):
            if not step.step_id:
                candidate = f"exploit-{i + 1}"
                while candidate in used_ids:
                    candidate = f"exploit-{uuid.uuid4().hex[:6]}"
                step.step_id = candidate
                used_ids.add(candidate)

        step_ids = {s.step_id for s in plan.steps if s.step_id}
        for step in plan.steps:
            step.depends_on = [d for d in step.depends_on if d in step_ids]

        plan.steps = self._topo_sort_steps(plan.steps)

        if not plan.success_criteria:
            plan.success_criteria = (
                "Confirm the target vulnerability via evidence captured by the steps."
            )
        return plan

    @staticmethod
    def _topo_sort_steps(steps: list) -> list:
        if not steps:
            return steps
        if len({s.step_id for s in steps}) != len(steps):
            return steps
        indeg: dict[str, int] = {s.step_id: 0 for s in steps}
        adj: dict[str, list[str]] = {s.step_id: [] for s in steps}
        for s in steps:
            for d in s.depends_on:
                adj[d].append(s.step_id)
                indeg[s.step_id] += 1

        remaining = list(steps)
        ordered: list = []
        while remaining:
            for s in remaining:
                if indeg[s.step_id] == 0:
                    ordered.append(s)
                    remaining.remove(s)
                    for nb in adj[s.step_id]:
                        indeg[nb] -= 1
                    break
            else:
                for s in steps:
                    s.depends_on = []
                return steps
        return ordered

    def _structural_check(self, plan: AttackPlan) -> list[str]:
        issues = []

        if not plan.plan_id:
            issues.append("Missing plan_id")

        if not plan.target.url:
            issues.append("Missing target URL")

        if not plan.vulnerability_hypothesis.type:
            issues.append("Missing vulnerability hypothesis type")

        if not plan.vulnerability_hypothesis.description:
            issues.append("Missing vulnerability hypothesis description")

        if not plan.steps:
            issues.append("Plan has no exploitation steps")
            return issues

        step_ids = set()
        for step in plan.steps:
            if not step.step_id:
                issues.append("Step missing step_id")
                continue
            if step.step_id in step_ids:
                issues.append(f"Duplicate step_id: {step.step_id}")
            step_ids.add(step.step_id)

            if not step.command:
                issues.append(f"Step {step.step_id} has no command")

            if not step.description:
                issues.append(f"Step {step.step_id} has no description")

            for dep in step.depends_on:
                if dep not in step_ids:
                    issues.append(
                        f"Step {step.step_id} depends on {dep} which hasn't been defined yet"
                    )

            self._check_circular_deps(plan.steps, issues)

            for i, fb in enumerate(step.fallbacks, start=1):
                if not fb.command:
                    issues.append(f"Fallback {i} for step {step.step_id} has no command")

        if not plan.success_criteria:
            issues.append("Missing overall success criteria")

        return issues

    def _check_circular_deps(self, steps: list, issues: list[str]) -> None:
        dep_graph: dict[str, set[str]] = {}
        for step in steps:
            dep_graph[step.step_id] = set(step.depends_on)

        visited: set[str] = set()
        in_stack: set[str] = set()

        def dfs(node: str) -> bool:
            if node in in_stack:
                return True
            if node in visited:
                return False
            visited.add(node)
            in_stack.add(node)
            for dep in dep_graph.get(node, set()):
                if dfs(dep):
                    return True
            in_stack.discard(node)
            return False

        for step_id in dep_graph:
            if step_id not in visited and dfs(step_id):
                issues.append(f"Circular dependency detected involving step {step_id}")
                break

    async def _semantic_check(
        self,
        plan: AttackPlan,
        graph: APIAssetGraph,
        findings: list[ReconFinding],
        rag_context: list[dict],
    ) -> SemanticVerdict:
        plan_json = plan.model_dump_json(indent=2)
        findings_summary = "\n".join(
            f"[{f.finding_id}] {f.finding_type}: {json.dumps(f.data)}"
            for f in findings
        ) if findings else "No findings."
        rag_text = "\n\n".join(
            r.get("content", "") for r in rag_context
        ) if rag_context else ""

        graph_summary = graph.summary()
        budget = prompt_token_budget(
            self.llm_client.config.context_window,
            self.llm_client.config.max_tokens,
        )
        skeleton = semantic_verification_prompt(
            plan_json=plan_json,
            graph_summary="",
            findings_summary="",
            rag_context="",
        )
        base_tokens = count_tokens(VERIFIER_SYSTEM) + count_tokens(skeleton)
        findings_summary, graph_summary, rag_text = allocate_blocks(
            [findings_summary, graph_summary, rag_text], max(0, budget - base_tokens)
        )

        prompt = semantic_verification_prompt(
            plan_json=plan_json,
            graph_summary=graph_summary,
            findings_summary=findings_summary,
            rag_context=rag_text,
        )

        messages = [
            {"role": "system", "content": VERIFIER_SYSTEM},
            {"role": "user", "content": prompt},
        ]

        try:
            return await self.llm_client.generate_json(
                messages, SemanticVerdict, purpose="plan_verification"
            )
        except Exception as exc:
            logger.error("semantic_verification_failed", error=str(exc))
            return SemanticVerdict(
                is_valid=True,
                semantic_issues=[],
                suggestions=[
                    f"Semantic verification could not run ({exc}); "
                    "plan accepted without semantic review.",
                ],
                verdict="Verification unavailable — plan accepted (fail-open)",
            )
