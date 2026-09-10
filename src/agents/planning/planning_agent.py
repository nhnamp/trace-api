from __future__ import annotations

from typing import Any

import structlog

from src.agents.base_agent import BaseAgent
from src.agents.planning.plan_generator import PlanGenerator
from src.agents.planning.recon_engine import ReconEngine
from src.config.settings import LLMProviderConfig, ReconConfig
from src.execution.tool_executor import ToolExecutor
from src.graph.api_asset_graph import APIAssetGraph
from src.knowledge.cve_lookup import CVELookupService
from src.knowledge.rag_engine import RAGEngine
from src.llm.logger import LLMLogger
from src.models.plan import AttackPlan, ValidationResult
from src.models.session import SessionState

logger = structlog.get_logger(__name__)


class PlanningAgent(BaseAgent):
    def __init__(
        self,
        llm_config: LLMProviderConfig,
        llm_logger: LLMLogger | None = None,
        tool_executor: ToolExecutor | None = None,
        rag_engine: RAGEngine | None = None,
        recon_config: ReconConfig | None = None,
        cve_lookup: CVELookupService | None = None,
        generate_fallbacks: bool = True,
    ) -> None:
        super().__init__(llm_config, llm_logger)
        self.tool_executor = tool_executor
        self.rag_engine = rag_engine
        self.recon_config = recon_config or ReconConfig()
        self.cve_lookup = cve_lookup
        self.plan_generator = PlanGenerator(self.llm_client, generate_fallbacks=generate_fallbacks)
        self._recon_engine: ReconEngine | None = None

    @property
    def name(self) -> str:
        return "planning"

    @property
    def recon_engine(self) -> ReconEngine:
        if self._recon_engine is None:
            if self.tool_executor is None:
                raise RuntimeError("PlanningAgent requires a ToolExecutor for recon")
            if self.rag_engine is None:
                raise RuntimeError("PlanningAgent requires a RAGEngine for recon")
            self._recon_engine = ReconEngine(
                llm_client=self.llm_client,
                tool_executor=self.tool_executor,
                rag_engine=self.rag_engine,
                config=self.recon_config,
                cve_lookup=self.cve_lookup,
            )
        return self._recon_engine

    async def run(self, input_data: Any) -> Any:
        if isinstance(input_data, SessionState):
            return await self.run_full(input_data)
        raise TypeError(f"PlanningAgent.run expects SessionState, got {type(input_data)}")

    async def run_full(self, session: SessionState) -> SessionState:
        await self.run_recon(session)
        await self.generate_plan(session)
        return session

    async def run_recon(self, session: SessionState) -> None:
        graph = APIAssetGraph.from_dict(session.api_graph_data)

        logger.info(
            "planning_recon_start",
            session_id=session.session_id,
            target=session.target.url,
            existing_findings=len(session.recon_results),
        )

        findings, rag_results = await self.recon_engine.run_recon(
            target_url=session.target.url,
            cve_id=session.target.cve_id,
            graph=graph,
            existing_findings=session.recon_results,
        )

        session.recon_results = findings
        session.api_graph_data = graph.to_dict()
        session.rag_context = rag_results
        session.touch()

        logger.info(
            "planning_recon_complete",
            session_id=session.session_id,
            findings=len(findings),
            graph_nodes=graph.node_count,
            rag_hits=len(rag_results),
        )

    async def generate_plan(
        self,
        session: SessionState,
        validation_feedback: ValidationResult | None = None,
    ) -> AttackPlan:
        graph = APIAssetGraph.from_dict(session.api_graph_data)

        logger.info(
            "planning_plan_start",
            session_id=session.session_id,
            findings=len(session.recon_results),
            graph_nodes=graph.node_count,
            has_feedback=validation_feedback is not None,
        )

        previous_plan = session.attack_plan if validation_feedback is not None else None

        plan = await self.plan_generator.generate_plan(
            target_url=session.target.url,
            cve_id=session.target.cve_id,
            graph=graph,
            findings=session.recon_results,
            rag_context=session.rag_context,
            validation_feedback=validation_feedback,
            previous_plan=previous_plan,
        )

        session.attack_plan = plan
        session.touch()

        logger.info(
            "planning_plan_complete",
            session_id=session.session_id,
            plan_id=plan.plan_id,
            steps=len(plan.steps),
        )
        return plan
