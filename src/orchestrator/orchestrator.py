from __future__ import annotations

import uuid
from pathlib import Path

import structlog

from src.agents.exploiting.exploiting_agent import ExploitingAgent, ExploitResult
from src.agents.planning.planning_agent import PlanningAgent
from src.agents.reporting.reporting_agent import ReportingAgent
from src.config.settings import SystemConfig
from src.execution.http_client import HTTPClient
from src.execution.tool_executor import ToolExecutor
from src.graph.api_asset_graph import APIAssetGraph
from src.knowledge.cve_lookup import CVELookupService, OpenCVEClient
from src.knowledge.rag_engine import RAGEngine
from src.llm.client import LLMClient, LLMError
from src.llm.logger import LLMLogger
from src.models.evidence import StepStatus
from src.models.plan import (
    AttackPlan,
    PlanStep,
    PlanTarget,
    ValidationResult,
    VulnerabilityHypothesis,
)
from src.models.report import ReportInput, ReportOutput
from src.models.session import FailureRecord, FSMState, SessionState
from src.models.target import TargetInfo
from src.orchestrator.plan_verifier import PlanVerifier
from src.orchestrator.replan_controller import ReplanAction, ReplanController
from src.orchestrator.session_manager import SessionManager
from src.orchestrator.state_machine import StateMachine

logger = structlog.get_logger(__name__)


class Orchestrator:
    def __init__(
        self,
        config: SystemConfig,
        rag_engine: RAGEngine | None = None,
        work_dir: str | None = None,
    ):
        self.config = config
        self.state_machine = StateMachine()
        self.session_manager = SessionManager(config.session)
        self.tool_executor = ToolExecutor(config.execution, work_dir=work_dir)
        self.rag_engine = rag_engine
        self.replan_controller = ReplanController(
            config.orchestrator.max_replans,
            config.orchestrator.max_exploit_replans,
        )

    async def initialize_session(self, target: TargetInfo) -> SessionState:
        session = self.session_manager.create(target)
        logger.info(
            "session_initialized",
            session_id=session.session_id,
            target=target.url,
        )
        return session

    async def validate_target(self, session: SessionState) -> bool:
        target_url = session.target.url
        logger.info("validating_target", url=target_url)

        result = await self.tool_executor.execute(
            f"curl -sSI -o /dev/null -w '%{{http_code}}' --connect-timeout 10 --max-time 15 {target_url}",
            timeout=20,
        )

        if result.success and result.stdout.strip() not in ("000", ""):
            http_code = result.stdout.strip()
            self.state_machine.transition(session, "receive_target")
            session.target.metadata["http_status"] = http_code
            session.target.metadata["reachable"] = True
            self.session_manager.save(session)
            logger.info(
                "target_validated",
                session_id=session.session_id,
                http_code=http_code,
            )
            return True

        session.target.metadata["reachable"] = False
        session.target.metadata["error"] = result.stderr or "Target unreachable"
        session.failure_history.append(
            FailureRecord(
                state=session.fsm_state,
                error=f"Target unreachable: {result.stderr}",
                recovery_action="check_target_url",
            )
        )
        self.state_machine.transition(session, "receive_target")
        self.session_manager.save(session)
        logger.warning(
            "target_unreachable",
            session_id=session.session_id,
            error=result.stderr,
        )
        return False

    def _first_discovered_path(self, session: SessionState) -> str:
        for f in session.recon_results:
            data = getattr(f, "data", {}) or {}
            for key in ("path", "endpoint", "url"):
                val = data.get(key)
                if isinstance(val, str) and val.startswith("/"):
                    return val
        try:
            graph = APIAssetGraph.from_dict(session.api_graph_data)
            for ep in graph.get_endpoints():
                path = (ep.get("properties", {}) or {}).get("path")
                if isinstance(path, str) and path.startswith("/"):
                    return path
        except Exception:  # noqa: BLE001 — graph parsing is best-effort here
            pass
        return "/"

    def _synthesize_minimal_plan(self, session: SessionState, reason: str) -> AttackPlan:
        existing = session.attack_plan
        if (
            existing is not None
            and existing.vulnerability_hypothesis
            and existing.vulnerability_hypothesis.type
        ):
            hypothesis = existing.vulnerability_hypothesis
        else:
            hypothesis = VulnerabilityHypothesis(
                type="unknown",
                description=(
                    "Automated planning could not derive a specific exploit; "
                    f"probing the discovered surface. ({reason})"
                ),
                confidence="low",
            )
        url = session.target.url.rstrip("/")
        path = self._first_discovered_path(session)
        step = PlanStep(
            step_id="exploit-1",
            description="Probe the target endpoint for the hypothesised vulnerability",
            command=f"curl -sSi {url}{path}",
            expected_result="A response from the target",
            success_criteria="A response is received from the target endpoint",
            is_critical=False,
        )
        return AttackPlan(
            plan_id=f"plan-{uuid.uuid4().hex[:8]}",
            target=PlanTarget(url=session.target.url, cve_id=session.target.cve_id),
            vulnerability_hypothesis=hypothesis,
            steps=[step],
            success_criteria="Best-effort probe; see recon findings and hypothesis for context.",
            evidence_requirements=["Any response demonstrating the described impact"],
        )

    def _approve_synthesized_plan(self, session: SessionState, reason: str) -> None:
        session.attack_plan = self._synthesize_minimal_plan(session, reason)
        session.plan_validation = ValidationResult(
            is_valid=True,
            suggestions=[
                f"Synthesized fallback plan — planning could not produce a validated "
                f"plan ({reason}). Recorded so the run can still be scored.",
            ],
        )
        session.failure_history.append(
            FailureRecord(
                state=session.fsm_state,
                error=f"Planning fell back to a synthesized plan: {reason}",
                recovery_action="synthesized_plan",
            )
        )
        if session.fsm_state == FSMState.PLANNING_IN_PROGRESS:
            self.state_machine.transition(session, "plan_generated")
        self.state_machine.transition(session, "approve")
        self.session_manager.save(session)
        logger.warning(
            "plan_synthesized_fallback",
            session_id=session.session_id,
            plan_id=session.attack_plan.plan_id,
            reason=reason,
        )

    async def run_planning_phase(self, session: SessionState) -> SessionState:
        if session.fsm_state not in (
            FSMState.TARGET_RECEIVED,
            FSMState.PLANNING_IN_PROGRESS,
        ):
            raise RuntimeError(
                "Planning phase requires TARGET_RECEIVED or PLANNING_IN_PROGRESS "
                f"state, got {session.fsm_state.value}"
            )
        is_replan = session.fsm_state == FSMState.PLANNING_IN_PROGRESS

        llm_log_dir = Path(self.config.logging.llm_log_dir)
        llm_logger = LLMLogger.for_session(session, llm_log_dir)

        cve_lookup: CVELookupService | None = None
        if self.config.cve_lookup.enabled:
            cve_client = OpenCVEClient(self.config.cve_lookup)
            alt_name_llm = None
            if self.config.cve_lookup.use_llm_alt_names:
                alt_name_llm = LLMClient(self.config.llm.planning, llm_logger)
            cve_lookup = CVELookupService(
                client=cve_client,
                config=self.config.cve_lookup,
                llm_client=alt_name_llm,
            )

        planning_agent = PlanningAgent(
            llm_config=self.config.llm.planning,
            llm_logger=llm_logger,
            tool_executor=self.tool_executor,
            rag_engine=self.rag_engine,
            recon_config=self.config.recon,
            cve_lookup=cve_lookup,
            generate_fallbacks=self.config.orchestrator.plan_fallbacks_enabled,
        )

        verifier_client = LLMClient(self.config.llm.verifier, llm_logger)
        plan_verifier = PlanVerifier(verifier_client)

        if not is_replan:
            self.state_machine.transition(session, "start_recon")
            self.session_manager.save(session)

            await planning_agent.run_recon(session)
            self.session_manager.save(session)

            if not session.recon_results:
                session.failure_history.append(
                    FailureRecord(
                        state=session.fsm_state,
                        error="Reconnaissance produced no findings",
                        recovery_action="plan_from_target_only",
                    )
                )
                logger.warning("recon_no_findings", session_id=session.session_id)

            self.state_machine.transition(session, "recon_complete")
            self.session_manager.save(session)

        validation_feedback = (
            self._exploitation_feedback(session) if is_replan else None
        )
        generation_retries = 0
        max_generation_retries = self.config.orchestrator.max_generation_retries
        while True:
            malformed_feedback: ValidationResult | None = None
            malformed_reason = ""
            try:
                await planning_agent.generate_plan(session, validation_feedback)
            except LLMError as exc:
                malformed_reason = f"generation error: {exc}"
                malformed_feedback = ValidationResult(
                    is_valid=False,
                    semantic_issues=[f"Plan generation did not return a usable plan: {exc}"],
                    suggestions=[
                        "Emit a single strict JSON object matching the AttackPlan "
                        "schema — no prose, no markdown fences.",
                    ],
                )
            else:
                if not session.attack_plan.steps:
                    malformed_reason = "plan returned with no exploitation steps"
                    malformed_feedback = ValidationResult(
                        is_valid=False,
                        structural_issues=[
                            "The plan was returned WITHOUT any exploitation steps: "
                            "the \"steps\" array was missing or empty."
                        ],
                        suggestions=[
                            "Output ONE complete JSON object whose \"steps\" array is "
                            "NON-EMPTY; every step needs a concrete \"command\". Do NOT "
                            "stop after the hypothesis or preconditions.",
                        ],
                    )

            if malformed_feedback is not None:
                session.plan_validation = malformed_feedback
                self.session_manager.save(session)
                logger.warning(
                    "plan_generation_malformed",
                    session_id=session.session_id,
                    reason=malformed_reason,
                    generation_retries=generation_retries,
                )
                if generation_retries < max_generation_retries:
                    generation_retries += 1
                    validation_feedback = malformed_feedback
                    continue

                self._approve_synthesized_plan(
                    session, f"{malformed_reason} after {generation_retries} retries"
                )
                break

            self.session_manager.save(session)

            self.state_machine.transition(session, "plan_generated")
            self.session_manager.save(session)

            graph = APIAssetGraph.from_dict(session.api_graph_data)
            validation = await plan_verifier.verify(
                session.attack_plan,
                graph,
                session.recon_results,
                session.rag_context,
            )
            session.plan_validation = validation
            self.session_manager.save(session)

            if validation.is_valid:
                self.state_machine.transition(session, "approve")
                self.session_manager.save(session)
                logger.info(
                    "plan_approved",
                    session_id=session.session_id,
                    plan_id=session.attack_plan.plan_id,
                )
                break

            action = self.replan_controller.decide(session, validation)
            validation_feedback = validation

            if action == ReplanAction.FAIL:
                if session.attack_plan is not None and not validation.structural_issues:
                    self.state_machine.transition(session, "approve")
                    self.session_manager.save(session)
                    logger.info(
                        "plan_approved_despite_semantic_issues",
                        session_id=session.session_id,
                        plan_id=session.attack_plan.plan_id,
                        semantic_issues=len(validation.semantic_issues),
                    )
                    break

                self._approve_synthesized_plan(
                    session, "max replans reached and plan could not be validated"
                )
                break

            if action == ReplanAction.REJECT_TO_RECON:
                self.state_machine.transition(session, "reject_to_recon")
                self.session_manager.save(session)

                await planning_agent.run_recon(session)
                self.session_manager.save(session)

                self.state_machine.transition(session, "recon_complete")
                self.session_manager.save(session)
            else:
                self.state_machine.transition(session, "reject_to_planning")
                self.session_manager.save(session)

        return session

    def _exploitation_feedback(self, session: SessionState) -> ValidationResult:
        failed = [
            r for r in session.exploit_trace
            if r.status in (StepStatus.FAILED, StepStatus.FALLBACK_USED)
        ]
        issues: list[str] = []
        for r in failed[:5]:
            detail = (r.stderr or r.stdout or "").strip().replace("\n", " ")
            issues.append(
                f"Step '{r.step_id}' ({r.step_description}) failed: "
                f"command `{r.command[:160]}` → {detail[:160] or 'no output'}"
            )
        if not issues:
            issues.append(
                "The previous plan executed without producing evidence of the "
                "vulnerability. The exploitation approach did not confirm the flaw."
            )
        return ValidationResult(
            is_valid=False,
            semantic_issues=issues,
            suggestions=[
                "The previous plan was validated but failed during exploitation. "
                "Revise the attack steps: reconsider the target endpoint/path, the "
                "payload encoding, and the success criteria based on the failures "
                "above. Do not repeat the exact same commands.",
            ],
        )

    async def run_exploitation_phase(self, session: SessionState) -> SessionState:
        if session.fsm_state != FSMState.EXPLOITATION_IN_PROGRESS:
            raise RuntimeError(
                f"Exploitation phase requires EXPLOITATION_IN_PROGRESS state, "
                f"got {session.fsm_state.value}"
            )
        if session.attack_plan is None:
            raise RuntimeError("No attack plan in session — cannot run exploitation")

        llm_log_dir = Path(self.config.logging.llm_log_dir)
        llm_logger = LLMLogger.for_session(session, llm_log_dir)

        session_dir = Path(self.config.session.session_dir) / f"sess-{session.session_id}"
        artifact_dir = str(session_dir / "artifacts")

        exploiting_agent = ExploitingAgent(
            llm_config=self.config.llm.exploiting,
            llm_logger=llm_logger,
            tool_executor=self.tool_executor,
            http_client=HTTPClient(),
            orchestrator_config=self.config.orchestrator,
            artifact_dir=artifact_dir,
        )

        logger.info(
            "exploitation_phase_start",
            session_id=session.session_id,
            plan_id=session.attack_plan.plan_id,
        )

        exploit_result: ExploitResult = await exploiting_agent.execute_plan(session)
        self.session_manager.save(session)

        if exploit_result.has_evidence:
            self.state_machine.transition(session, "exploit_complete")
            self.session_manager.save(session)
            logger.info(
                "exploitation_succeeded",
                session_id=session.session_id,
                evidence_count=sum(1 for r in exploit_result.results if r.is_evidence),
            )
            return session

        if exploit_result.critical_failure and self.replan_controller.should_replan_exploit(session):
            session.exploit_replan_count += 1
            session.failure_history.append(
                FailureRecord(
                    state=session.fsm_state,
                    error=f"Critical exploitation failure: {exploit_result.summary}",
                    recovery_action="replan",
                )
            )
            self.state_machine.transition(session, "exploit_failed_replan")
            self.session_manager.save(session)
            logger.info(
                "exploitation_failed_replanning",
                session_id=session.session_id,
                exploit_replan_count=session.exploit_replan_count,
            )
            return session

        self.state_machine.transition(session, "exploit_failed")
        self.session_manager.save(session)
        logger.info(
            "exploitation_failed_reporting",
            session_id=session.session_id,
            summary=exploit_result.summary,
        )
        return session

    async def test_llm_connection(self, session: SessionState) -> bool:
        llm_log_dir = Path(self.config.logging.llm_log_dir)
        llm_logger = LLMLogger.for_session(session, llm_log_dir)
        client = LLMClient(self.config.llm.planning, llm_logger)

        try:
            response = await client.generate_text(
                "Respond with exactly: CONNECTION_OK",
                system="You are a connection test. Respond only with the exact text requested.",
                purpose="connection_test",
            )
            success = "CONNECTION_OK" in response
            logger.info(
                "llm_connection_test",
                session_id=session.session_id,
                success=success,
                model=client.config.model,
            )
            return success
        except Exception as exc:
            logger.warning(
                "llm_connection_failed",
                session_id=session.session_id,
                error=str(exc),
            )
            return False

    async def run_reporting_phase(self, session: SessionState) -> SessionState:
        if session.fsm_state != FSMState.REPORTING:
            raise RuntimeError(
                f"Reporting phase requires REPORTING state, got {session.fsm_state.value}"
            )

        llm_log_dir = Path(self.config.logging.llm_log_dir)
        llm_logger = LLMLogger.for_session(session, llm_log_dir)

        reporting_agent = ReportingAgent(
            llm_config=self.config.llm.reporting,
            llm_logger=llm_logger,
            report_config=self.config.report,
        )

        evidence_steps_flagged = sum(1 for s in session.exploit_trace if s.is_evidence)

        report_input = ReportInput(
            session_id=session.session_id,
            target=session.target,
            fsm_state=session.fsm_state,
            created_at=session.created_at,
            updated_at=session.updated_at,
            recon_results=session.recon_results,
            rag_context=session.rag_context,
            api_graph_data=session.api_graph_data,
            attack_plan=session.attack_plan,
            plan_validation=session.plan_validation,
            plan_revision_count=session.plan_revision_count,
            exploit_trace=session.exploit_trace,
            failure_history=session.failure_history,
        )

        logger.info(
            "reporting_phase_start",
            session_id=session.session_id,
            evidence_steps_flagged=evidence_steps_flagged,
        )

        try:
            report_output: ReportOutput = await reporting_agent.generate_report(report_input)
            session.report_path = report_output.report_path

            self.state_machine.transition(session, "report_generated")

            self.session_manager.save(session)
            logger.info(
                "reporting_phase_complete",
                session_id=session.session_id,
                report_path=report_output.report_path,
                final_state=session.fsm_state.value,
            )
        except Exception as exc:
            session.failure_history.append(
                FailureRecord(
                    state=session.fsm_state,
                    error=f"Report generation failed: {exc}",
                    recovery_action="retry_reporting",
                )
            )
            self.state_machine.transition(session, "fail")
            self.session_manager.save(session)
            logger.error(
                "reporting_phase_failed",
                session_id=session.session_id,
                error=str(exc),
            )

        return session

    async def run_session(self, target: TargetInfo) -> SessionState:
        session = await self.initialize_session(target)

        reachable = await self.validate_target(session)
        if not reachable:
            logger.warning(
                "session_aborted_unreachable",
                session_id=session.session_id,
            )
            self.state_machine.transition(session, "fail")
            self.session_manager.save(session)
            return session

        session = await self.run_planning_phase(session)
        if session.is_terminal:
            return session

        session = await self.run_exploitation_phase(session)

        max_replan_cycles = self.config.orchestrator.max_exploit_replans + 2
        cycles = 0
        while (
            session.fsm_state == FSMState.PLANNING_IN_PROGRESS
            and cycles < max_replan_cycles
        ):
            cycles += 1
            session = await self.run_planning_phase(session)
            if session.is_terminal:
                return session
            session = await self.run_exploitation_phase(session)

        if session.fsm_state == FSMState.REPORTING:
            session = await self.run_reporting_phase(session)

        if session.fsm_state == FSMState.PLANNING_IN_PROGRESS:
            logger.warning(
                "run_session_forced_terminal",
                session_id=session.session_id, state=session.fsm_state.value,
            )
            self.state_machine.transition(session, "fail")
            self.session_manager.save(session)

        return session

    def get_session(self, session_id: str) -> SessionState:
        return self.session_manager.load(session_id)

    def list_sessions(self) -> list[dict]:
        return self.session_manager.list_sessions()
