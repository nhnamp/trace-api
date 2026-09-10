from __future__ import annotations

from pathlib import Path
from typing import Any

import structlog
from jinja2 import Environment, FileSystemLoader

from src.agents.base_agent import BaseAgent
from src.config.settings import ReportConfig
from src.graph.api_asset_graph import APIAssetGraph
from src.llm.prompts.reporting import (
    CONCLUSION_SYSTEM,
    EXECUTIVE_SUMMARY_SYSTEM,
    REMEDIATION_SYSTEM,
    build_conclusion_prompt,
    build_executive_summary_prompt,
    build_remediation_prompt,
)
from src.models.evidence import ExploitStepResult, StepStatus
from src.models.report import ReportInput, ReportOutput

logger = structlog.get_logger(__name__)

TEMPLATE_DIR = Path(__file__).parent / "templates"


class ReportingAgent(BaseAgent):
    @property
    def name(self) -> str:
        return "reporting"

    def __init__(self, *, report_config: ReportConfig | None = None, **kwargs: Any):
        super().__init__(**kwargs)
        self.report_config = report_config or ReportConfig()
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(TEMPLATE_DIR)),
            keep_trailing_newline=True,
            trim_blocks=True,
            lstrip_blocks=True,
        )

    async def run(self, input_data: Any) -> ReportOutput:
        if not isinstance(input_data, ReportInput):
            raise TypeError(f"Expected ReportInput, got {type(input_data).__name__}")
        return await self.generate_report(input_data)

    async def generate_report(self, report_input: ReportInput) -> ReportOutput:
        logger.info(
            "report_generation_start",
            session_id=report_input.session_id,
            target=report_input.target.url,
        )

        vuln_type, vuln_description = self._extract_vuln_info(report_input)
        evidence_steps = [s for s in report_input.exploit_trace if s.is_evidence]

        executive_summary = await self._generate_executive_summary(
            report_input, vuln_type, vuln_description, evidence_steps,
        )
        conclusion = await self._generate_conclusion(
            report_input, vuln_type, evidence_steps,
        )
        remediation = None
        if self.report_config.include_remediation and vuln_type and vuln_type != "Unknown":
            remediation = await self._generate_remediation(
                report_input, vuln_type, vuln_description, evidence_steps,
            )

        graph_summary = self._build_graph_summary(report_input.api_graph_data)

        template = self.jinja_env.get_template("report.md.j2")
        title = report_input.target.cve_id or report_input.target.url
        report_md = template.render(
            title=title,
            session_id=report_input.session_id,
            target=report_input.target,
            fsm_state=report_input.fsm_state.value,
            created_at=report_input.created_at.isoformat(),
            updated_at=report_input.updated_at.isoformat(),
            plan_revision_count=report_input.plan_revision_count,
            recon_results=report_input.recon_results,
            rag_context=report_input.rag_context,
            graph_summary=graph_summary,
            attack_plan=report_input.attack_plan,
            exploit_trace=report_input.exploit_trace,
            evidence_steps=evidence_steps,
            executive_summary=executive_summary,
            conclusion=conclusion,
            remediation=remediation,
            include_raw_logs=self.report_config.include_raw_logs,
            failure_history=report_input.failure_history,
        )

        report_path = self._write_report(report_input, report_md)

        summary = self._build_short_summary(
            report_input, evidence_steps,
        )

        logger.info(
            "report_generation_complete",
            session_id=report_input.session_id,
            report_path=str(report_path),
            evidence_steps_flagged=len(evidence_steps),
        )

        return ReportOutput(report_path=str(report_path), summary=summary)

    async def _generate_executive_summary(
        self,
        report_input: ReportInput,
        vuln_type: str,
        vuln_description: str,
        evidence_steps: list[ExploitStepResult],
    ) -> str:
        recon_summary = self._summarize_recon(report_input)
        exploit_summary = self._summarize_exploitation(report_input)

        prompt = build_executive_summary_prompt(
            target_url=report_input.target.url,
            cve_id=report_input.target.cve_id,
            vuln_type=vuln_type,
            vuln_description=vuln_description,
            evidence_count=len(evidence_steps),
            recon_summary=recon_summary,
            exploit_summary=exploit_summary,
        )

        try:
            return await self.llm_client.generate_text(
                prompt,
                system=EXECUTIVE_SUMMARY_SYSTEM,
                purpose="report_executive_summary",
            )
        except Exception as exc:
            logger.warning("executive_summary_llm_failed", error=str(exc))
            return self._fallback_executive_summary(report_input, evidence_steps)

    async def _generate_conclusion(
        self,
        report_input: ReportInput,
        vuln_type: str,
        evidence_steps: list[ExploitStepResult],
    ) -> str:
        evidence_details = self._format_evidence_details(evidence_steps)
        failure_details = self._format_failure_steps(report_input.exploit_trace)
        limitations = self._format_limitations(report_input)

        prompt = build_conclusion_prompt(
            target_url=report_input.target.url,
            cve_id=report_input.target.cve_id,
            evidence_count=len(evidence_steps),
            vuln_type=vuln_type,
            evidence_details=evidence_details,
            failure_details=failure_details,
            limitations=limitations,
        )

        try:
            return await self.llm_client.generate_text(
                prompt,
                system=CONCLUSION_SYSTEM,
                purpose="report_conclusion",
            )
        except Exception as exc:
            logger.warning("conclusion_llm_failed", error=str(exc))
            return self._fallback_conclusion(report_input, evidence_steps)

    async def _generate_remediation(
        self,
        report_input: ReportInput,
        vuln_type: str,
        vuln_description: str,
        evidence_steps: list[ExploitStepResult],
    ) -> str:
        evidence_details = self._format_evidence_details(evidence_steps)
        target_tech = self._infer_target_tech(report_input)

        prompt = build_remediation_prompt(
            vuln_type=vuln_type,
            vuln_description=vuln_description,
            target_tech=target_tech,
            cve_id=report_input.target.cve_id,
            evidence_details=evidence_details,
        )

        try:
            return await self.llm_client.generate_text(
                prompt,
                system=REMEDIATION_SYSTEM,
                purpose="report_remediation",
            )
        except Exception as exc:
            logger.warning("remediation_llm_failed", error=str(exc))
            return f"Remediation guidance could not be generated. Address the identified {vuln_type} vulnerability according to security best practices."

    def _extract_vuln_info(self, report_input: ReportInput) -> tuple[str, str]:
        if report_input.attack_plan and report_input.attack_plan.vulnerability_hypothesis:
            hyp = report_input.attack_plan.vulnerability_hypothesis
            return hyp.type, hyp.description
        return "Unknown", "No vulnerability hypothesis was generated."

    def _build_graph_summary(self, api_graph_data: dict) -> str:
        if not api_graph_data:
            return ""
        try:
            graph = APIAssetGraph.from_dict(api_graph_data)
            if graph.node_count == 0:
                return ""
            return graph.summary()
        except Exception:
            return ""

    def _summarize_recon(self, report_input: ReportInput) -> str:
        if not report_input.recon_results:
            return "No reconnaissance was performed."
        finding_types = {}
        for f in report_input.recon_results:
            finding_types[f.finding_type] = finding_types.get(f.finding_type, 0) + 1
        parts = [f"{count} {ftype}" for ftype, count in finding_types.items()]
        return f"Reconnaissance produced {len(report_input.recon_results)} finding(s): {', '.join(parts)}."

    def _summarize_exploitation(self, report_input: ReportInput) -> str:
        if not report_input.exploit_trace:
            return "No exploitation steps were executed."
        total = len(report_input.exploit_trace)
        succeeded = sum(1 for s in report_input.exploit_trace if s.status == StepStatus.SUCCESS)
        failed = sum(1 for s in report_input.exploit_trace if s.status == StepStatus.FAILED)
        evidence = sum(1 for s in report_input.exploit_trace if s.is_evidence)
        return (
            f"{total} step(s) executed: {succeeded} succeeded, {failed} failed. "
            f"{evidence} step(s) flagged as potential evidence by the automated judge."
        )

    def _format_evidence_details(self, evidence_steps: list[ExploitStepResult]) -> str:
        if not evidence_steps:
            return ""
        lines = []
        for step in evidence_steps:
            lines.append(f"- [{step.step_id}] {step.step_description}: {step.evidence_summary or 'flagged as evidence (no summary)'}")
        return "\n".join(lines)

    def _format_failure_steps(self, trace: list[ExploitStepResult]) -> str:
        failed = [s for s in trace if s.status == StepStatus.FAILED]
        if not failed:
            return ""
        lines = []
        for step in failed:
            error_hint = step.stderr[:200] if step.stderr else "No error output"
            lines.append(f"- [{step.step_id}] {step.step_description}: {error_hint}")
        return "\n".join(lines)

    def _format_limitations(self, report_input: ReportInput) -> str:
        limitations = []
        if report_input.plan_revision_count > 0:
            limitations.append(f"Plan was revised {report_input.plan_revision_count} time(s) before execution.")
        if not report_input.recon_results:
            limitations.append("No reconnaissance data was available.")
        graph = APIAssetGraph.from_dict(report_input.api_graph_data) if report_input.api_graph_data else None
        if graph and graph.node_count == 0:
            limitations.append("API Asset Graph was empty — endpoint grounding was limited.")
        if report_input.failure_history:
            limitations.append(f"{len(report_input.failure_history)} failure(s) occurred during the session.")
        return "\n".join(f"- {l}" for l in limitations) if limitations else ""

    def _infer_target_tech(self, report_input: ReportInput) -> str:
        techs = set()
        for finding in report_input.recon_results:
            if finding.finding_type in ("technology", "server", "framework"):
                tech_name = finding.data.get("name") or finding.data.get("technology")
                if tech_name:
                    techs.add(str(tech_name))
        for ctx in report_input.rag_context:
            lib = ctx.get("target_library")
            if lib:
                techs.add(str(lib))
        return ", ".join(sorted(techs)) if techs else "Unknown"

    def _fallback_executive_summary(
        self, report_input: ReportInput, evidence_steps: list[ExploitStepResult],
    ) -> str:
        target = report_input.target.url
        cve = report_input.target.cve_id or "an unspecified vulnerability"
        return (
            f"An automated penetration test was conducted against {target} targeting {cve}. "
            f"{len(report_input.exploit_trace)} exploitation step(s) were executed, of which "
            f"{len(evidence_steps)} were flagged as potential evidence. See the exploitation "
            f"trace and evidence sections for the raw commands and responses; the determination "
            f"of whether the vulnerability was actually exploited is left to the reviewer."
        )

    def _fallback_conclusion(
        self, report_input: ReportInput, evidence_steps: list[ExploitStepResult],
    ) -> str:
        return (
            f"{len(report_input.exploit_trace)} exploitation step(s) were executed and "
            f"{len(evidence_steps)} were flagged as potential evidence by the automated judge. "
            f"This report presents the commands, responses and observations as-is; whether they "
            f"constitute a successful exploitation of the targeted vulnerability should be "
            f"assessed by reviewing the evidence and logs directly."
        )

    def _write_report(self, report_input: ReportInput, report_md: str) -> Path:
        output_dir = Path(self.report_config.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        cve_slug = report_input.target.cve_id or "unknown"
        filename = f"{cve_slug}_{report_input.session_id}.md"
        report_path = output_dir / filename
        report_path.write_text(report_md, encoding="utf-8")

        session_dir = Path(self.report_config.output_dir).parent / "sessions" / f"sess-{report_input.session_id}"
        if session_dir.exists():
            session_copy = session_dir / "report.md"
            session_copy.write_text(report_md, encoding="utf-8")

        return report_path

    def _build_short_summary(
        self,
        report_input: ReportInput,
        evidence_steps: list[ExploitStepResult],
    ) -> str:
        target = report_input.target.cve_id or report_input.target.url
        return (
            f"{target} — {len(report_input.exploit_trace)} step(s) executed, "
            f"{len(evidence_steps)} flagged as evidence (success assessed externally)"
        )
