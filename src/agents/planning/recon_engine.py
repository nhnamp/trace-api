from __future__ import annotations

import json
import re
import uuid

import structlog
from pydantic import BaseModel

from src.config.settings import ReconConfig
from src.execution.dir_enum import COMMON_PARAM_NAMES, DirEnumerator
from src.execution.tool_executor import ToolExecutor
from src.graph.api_asset_graph import APIAssetGraph
from src.graph.edges import EdgeType
from src.graph.nodes import GraphNode, NodeType
from src.knowledge.cve_lookup import CVELookupResult, CVELookupService
from src.knowledge.rag_engine import RAGEngine
from src.llm.client import LLMClient
from src.llm.prompts.planning_recon import (
    RECON_SYSTEM,
    recon_command_prompt,
    recon_interpret_prompt,
)
from src.llm.token_budget import (
    allocate_blocks,
    count_tokens,
    prompt_token_budget,
    truncate_to_tokens,
)
from src.models.recon import ReconCommand, ReconFinding

logger = structlog.get_logger(__name__)

_RECON_CMD_STDOUT_TOKENS = 1200
_RECON_CMD_STDERR_TOKENS = 300

_ADVISORY_NAME_RE = re.compile(r"\b[a-z][a-z0-9]*(?:_[a-z0-9]+)+\b")
_ADVISORY_NAME_STOPWORDS = frozenset({
    "path_traversal", "access_control", "directory_traversal", "sql_injection",
    "command_injection", "remote_code", "code_execution", "cross_site",
    "request_forgery", "information_disclosure", "denial_of", "of_service",
})
_ADVISORY_MAX_NAMES = 6
_ADVISORY_MAX_PROBES = 40

_PARAM_PROBE_MAX_ENDPOINTS = 4

_PROTECTED_RESOURCE_PATHS: tuple[str, ...] = (
    "admin", "administrator", "admin/login", "admin/dashboard", "adminpanel",
    "admin-panel", "manage", "management", "manager", "console", "dashboard",
    "internal", "private", "secure", "restricted", "config", "configuration",
    "settings", "actuator", "actuator/env", "metrics", "debug", "users", "accounts",
    "account", "profile", "backup", "server-status", "api/admin", "api/internal",
    "api/private", "api/v1/admin", "v1/admin", "gateway/admin", "auth/admin",
)
_PROTECTED_STATUSES: frozenset[int] = frozenset({401, 403, 407})
_PROTECTED_MAX_PROBES = 60


class ReconCommandSet(BaseModel):
    commands: list[dict] = []
    reasoning: str = ""


class ReconInterpretation(BaseModel):
    findings: list[dict] = []
    graph_updates: list[dict] = []
    continue_recon: bool = False
    reasoning: str = ""


class ReconEngine:
    def __init__(
        self,
        llm_client: LLMClient,
        tool_executor: ToolExecutor,
        rag_engine: RAGEngine,
        config: ReconConfig,
        cve_lookup: CVELookupService | None = None,
    ) -> None:
        self.llm_client = llm_client
        self.tool_executor = tool_executor
        self.rag_engine = rag_engine
        self.config = config
        self.cve_lookup = cve_lookup

    async def run_recon(
        self,
        target_url: str,
        cve_id: str | None,
        graph: APIAssetGraph,
        existing_findings: list[ReconFinding],
    ) -> tuple[list[ReconFinding], list[dict]]:
        all_findings = self._dedup_findings(existing_findings)
        rag_results: list[dict] = []

        official = await self._fetch_official_cve_context(cve_id)

        initial_query = cve_id or target_url
        rag_hits = self.rag_engine.query(
            initial_query,
            mode="direct" if cve_id else "hybrid",
            n_results=3,
        )
        if not rag_hits and cve_id:
            rag_hits = self.rag_engine.query(
                official or cve_id, mode="hybrid", n_results=3
            )

        rag_results = [r.model_dump() for r in rag_hits]
        rag_context = "\n\n".join(r.content for r in rag_hits) if rag_hits else ""

        if official:
            rag_context = f"{official}\n\n{rag_context}".strip()
            rag_results.insert(0, {
                "doc_id": f"opencve:{cve_id}",
                "cve_id": cve_id,
                "content": official,
                "source": "opencve",
                "score": 1.0,
            })

        if self.config.dir_enum.enabled and not graph.get_endpoints():
            enum_findings = await self._run_dir_enumeration(target_url, graph)
            all_findings = self._dedup_findings(all_findings + enum_findings)

        for iteration in range(1, self.config.max_iterations + 1):
            logger.info(
                "recon_iteration_start",
                iteration=iteration,
                max_iterations=self.config.max_iterations,
                findings_count=len(all_findings),
                graph_nodes=graph.node_count,
            )

            commands = await self._generate_commands(
                target_url, cve_id, graph, all_findings, iteration, rag_context
            )
            if not commands:
                logger.info("recon_no_commands_generated", iteration=iteration)
                break

            command_results = await self._execute_commands(commands)

            interpretation = await self._interpret_results(
                target_url, command_results, graph, iteration
            )

            new_findings = self._process_findings(interpretation, commands)
            all_findings = self._dedup_findings(all_findings + new_findings)

            self._apply_graph_updates(graph, interpretation.graph_updates)

            new_cve_hits = await self._lookup_new_products(graph)
            for hit in new_cve_hits:
                if hit.doc_id not in {r.get("doc_id") for r in rag_results}:
                    rag_results.append(hit.model_dump())
                    rag_context += f"\n\n{hit.content}"

            if not interpretation.continue_recon:
                logger.info(
                    "recon_complete",
                    iteration=iteration,
                    reason=interpretation.reasoning,
                    total_findings=len(all_findings),
                )
                break

            if iteration < self.config.max_iterations:
                tech_query = graph.summary()
                if tech_query and len(tech_query) > 50:
                    additional_hits = self.rag_engine.query(
                        tech_query, mode="hybrid", n_results=3
                    )
                    for hit in additional_hits:
                        if hit.doc_id not in {r.get("doc_id") for r in rag_results}:
                            rag_results.append(hit.model_dump())
                            rag_context += f"\n\n{hit.content}"

        if self.config.dir_enum.enabled and official:
            adv_findings = await self._advisory_endpoint_probe(target_url, graph, official)
            if adv_findings:
                all_findings = self._dedup_findings(all_findings + adv_findings)

        if self.config.dir_enum.enabled:
            protected_findings = await self._probe_protected_resources(target_url, graph)
            if protected_findings:
                all_findings = self._dedup_findings(all_findings + protected_findings)

        if self.config.dir_enum.enabled and self.config.dir_enum.bypass_probe_enabled:
            bypass_findings = await self._probe_bypass_routes(target_url, graph)
            if bypass_findings:
                all_findings = self._dedup_findings(all_findings + bypass_findings)

        if self.config.dir_enum.enabled:
            param_findings = await self._probe_parameters(target_url, graph)
            if param_findings:
                all_findings = self._dedup_findings(all_findings + param_findings)

        return all_findings, rag_results

    @staticmethod
    def _extract_advisory_names(advisory: str) -> list[str]:
        names: list[str] = []
        seen: set[str] = set()
        for m in _ADVISORY_NAME_RE.findall(advisory or ""):
            if m in _ADVISORY_NAME_STOPWORDS or m in seen:
                continue
            seen.add(m)
            names.append(m)
            if len(names) >= _ADVISORY_MAX_NAMES:
                break
        return names

    async def _advisory_endpoint_probe(
        self, target_url: str, graph: APIAssetGraph, advisory: str
    ) -> list[ReconFinding]:
        names = self._extract_advisory_names(advisory)
        if not names:
            return []

        bases = [""]
        for ep in graph.get_endpoints():
            path = (ep.get("properties") or {}).get("path") or ""
            p = path.strip("/")
            if p and p not in bases:
                bases.append(p)

        entries: list[str] = []
        seen: set[str] = set()
        for base in bases:
            for name in names:
                entry = f"{base}/{name}".strip("/") if base else name
                if entry not in seen:
                    seen.add(entry)
                    entries.append(entry)
        entries = entries[:_ADVISORY_MAX_PROBES]

        try:
            results = await DirEnumerator(self.config.dir_enum).probe_paths(target_url, entries)
        except Exception as exc:  # noqa: BLE001 — must not crash recon
            logger.warning("advisory_probe_failed", error=str(exc))
            return []

        findings: list[ReconFinding] = []
        for r in results:
            ep_id = f"endpoint:{r.path}"
            if not graph.has_node(ep_id):
                graph.add_node(GraphNode(
                    node_id=ep_id,
                    node_type=NodeType.ENDPOINT,
                    properties={
                        "path": r.path,
                        "base_url": target_url,
                        "discovered_by": "advisory_probe",
                        "status_code": r.status_code,
                        "content_type": r.content_type,
                    },
                ))
            findings.append(ReconFinding(
                finding_id=f"advprobe-{uuid.uuid4().hex[:6]}",
                source_command=f"advisory_probe {target_url}",
                finding_type="endpoint",
                data={
                    "path": r.path,
                    "status_code": r.status_code,
                    "content_type": r.content_type,
                    "discovered_by": "named in the CVE advisory",
                },
                raw_output=f"{r.status_code} {r.path} (advisory-named)",
            ))

        logger.info(
            "advisory_endpoint_probe",
            target=target_url, names=names, probed=len(entries), found=len(findings),
        )
        return findings

    async def _probe_protected_resources(
        self, target_url: str, graph: APIAssetGraph
    ) -> list[ReconFinding]:
        bases = [""]
        for ep in graph.get_endpoints():
            p = ((ep.get("properties") or {}).get("path") or "").strip("/")
            if p and p not in bases:
                bases.append(p)

        entries: list[str] = []
        seen: set[str] = set()
        for base in bases:
            for name in _PROTECTED_RESOURCE_PATHS:
                entry = f"{base}/{name}".strip("/") if base else name
                if entry not in seen:
                    seen.add(entry)
                    entries.append(entry)
        entries = entries[:_PROTECTED_MAX_PROBES]

        try:
            results = await DirEnumerator(self.config.dir_enum).probe_paths(target_url, entries)
        except Exception as exc:  # noqa: BLE001 — must not crash recon
            logger.warning("protected_probe_failed", error=str(exc))
            return []

        findings: list[ReconFinding] = []
        for r in results:
            if r.status_code not in _PROTECTED_STATUSES:
                continue
            ep_id = f"endpoint:{r.path}"
            props = {
                "path": r.path,
                "base_url": target_url,
                "discovered_by": "protected_probe",
                "status_code": r.status_code,
                "content_type": r.content_type,
                "access": "protected",
                "baseline_status": r.status_code,
            }
            if graph.has_node(ep_id):
                graph.graph.nodes[ep_id]["properties"].update(
                    {"access": "protected", "baseline_status": r.status_code}
                )
            else:
                graph.add_node(GraphNode(
                    node_id=ep_id, node_type=NodeType.ENDPOINT, properties=props,
                ))
            findings.append(ReconFinding(
                finding_id=f"protected-{uuid.uuid4().hex[:6]}",
                source_command=f"protected_probe {target_url}",
                finding_type="protected_endpoint",
                data={
                    "path": r.path,
                    "baseline_status": r.status_code,
                    "access": "protected",
                    "note": (
                        "Route exists but is access-controlled when requested "
                        "directly; a successful access-control bypass would return "
                        "content instead of this status."
                    ),
                },
                raw_output=f"{r.status_code} {r.path} (protected — direct access blocked)",
            ))

        logger.info(
            "protected_resource_probe",
            target=target_url, probed=len(entries), protected=len(findings),
        )
        return findings

    async def _probe_bypass_routes(
        self, target_url: str, graph: APIAssetGraph
    ) -> list[ReconFinding]:
        public_bases: list[str] = []
        for ep in sorted(
            graph.get_endpoints(),
            key=lambda e: len(((e.get("properties") or {}).get("path") or "")),
        ):
            props = ep.get("properties") or {}
            status = props.get("status_code")
            path = (props.get("path") or "").strip("/")
            if path and isinstance(status, int) and 200 <= status < 300 and path not in public_bases:
                public_bases.append(path)
        if not public_bases:
            return []

        try:
            hits = await DirEnumerator(self.config.dir_enum).probe_bypass(
                target_url, public_bases, _PROTECTED_RESOURCE_PATHS
            )
        except Exception as exc:  # noqa: BLE001 — must not crash recon
            logger.warning("bypass_probe_failed", error=str(exc))
            return []

        findings: list[ReconFinding] = []
        for h in hits:
            ep_id = f"endpoint:{h.path}"
            props = {
                "path": h.path,
                "base_url": target_url,
                "discovered_by": "bypass_probe",
                "status_code": h.status_code,
                "access": "bypass-reachable",
                "bypass_base": h.base,
                "bypass_vector": h.vector,
            }
            if graph.has_node(ep_id):
                graph.graph.nodes[ep_id]["properties"].update({
                    "access": "bypass-reachable", "bypass_vector": h.vector, "bypass_base": h.base,
                })
            else:
                graph.add_node(GraphNode(
                    node_id=ep_id, node_type=NodeType.ENDPOINT, properties=props,
                ))
            findings.append(ReconFinding(
                finding_id=f"bypass-{uuid.uuid4().hex[:6]}",
                source_command=f"bypass_probe {target_url}{h.path}",
                finding_type="bypass_reachable_route",
                data={
                    "path": h.path,
                    "public_base": h.base,
                    "bypass_vector": h.vector,
                    "status_code": h.status_code,
                    "response_excerpt": h.body_excerpt,
                    "note": (
                        "A traversal bypass from the public base returned content the "
                        "base does not normally serve — the protected route is reachable "
                        "via this vector. Target THIS path/vector to prove the bypass."
                    ),
                },
                raw_output=f"{h.status_code} {h.path} via {h.vector} (bypass-reachable)",
            ))

        logger.info(
            "bypass_route_probe",
            target=target_url, bases=len(public_bases), reachable=len(findings),
        )
        return findings

    async def _probe_parameters(
        self, target_url: str, graph: APIAssetGraph
    ) -> list[ReconFinding]:
        endpoints = graph.get_endpoints()
        if not endpoints:
            return []

        def _relevance(ep: dict) -> int:
            return 0 if (ep.get("properties") or {}).get("discovered_by") == "advisory_probe" else 1

        paths: list[str] = []
        for ep in sorted(endpoints, key=_relevance):
            path = (ep.get("properties") or {}).get("path") or ""
            if path and path not in paths:
                paths.append(path)
        paths = paths[:_PARAM_PROBE_MAX_ENDPOINTS]

        findings: list[ReconFinding] = []
        for path in paths:
            try:
                params = await DirEnumerator(self.config.dir_enum).probe_params(
                    target_url, path, COMMON_PARAM_NAMES
                )
            except Exception as exc:  # noqa: BLE001 — must not crash recon
                logger.warning("param_probe_failed", path=path, error=str(exc))
                continue
            for name in params:
                findings.append(ReconFinding(
                    finding_id=f"param-{uuid.uuid4().hex[:6]}",
                    source_command=f"param_probe {target_url}{path}",
                    finding_type="parameter",
                    data={
                        "endpoint_path": path,
                        "name": name,
                        "location": "query",
                        "discovered_by": "response differs from baseline",
                    },
                    raw_output=f"{path}?{name}= reacts (differs from junk-param baseline)",
                ))

        if findings:
            logger.info(
                "parameter_probe",
                target=target_url, endpoints=len(paths), params_found=len(findings),
            )
        return findings

    async def _generate_commands(
        self,
        target_url: str,
        cve_id: str | None,
        graph: APIAssetGraph,
        findings: list[ReconFinding],
        iteration: int,
        rag_context: str,
    ) -> list[ReconCommand]:
        findings_summary = self._summarize_findings(findings)

        graph_summary = graph.summary()
        budget = prompt_token_budget(
            self.llm_client.config.context_window,
            self.llm_client.config.max_tokens,
        )
        skeleton = recon_command_prompt(
            target_url=target_url,
            cve_id=cve_id,
            graph_summary="",
            previous_findings="",
            iteration=iteration,
            max_iterations=self.config.max_iterations,
            rag_context="",
        )
        base_tokens = count_tokens(RECON_SYSTEM) + count_tokens(skeleton)
        findings_summary, graph_summary, rag_context = allocate_blocks(
            [findings_summary, graph_summary, rag_context], max(0, budget - base_tokens)
        )

        prompt = recon_command_prompt(
            target_url=target_url,
            cve_id=cve_id,
            graph_summary=graph_summary,
            previous_findings=findings_summary,
            iteration=iteration,
            max_iterations=self.config.max_iterations,
            rag_context=rag_context,
        )

        messages = [
            {"role": "system", "content": RECON_SYSTEM},
            {"role": "user", "content": prompt},
        ]

        try:
            result = await self.llm_client.generate_json(
                messages, ReconCommandSet, purpose="recon_command_generation"
            )
        except Exception as exc:
            logger.error("recon_command_generation_failed", error=str(exc))
            return []

        commands = []
        for cmd_data in result.commands[: self.config.max_commands_per_iteration]:
            commands.append(
                ReconCommand(
                    command_id=cmd_data.get("command_id", f"recon-{uuid.uuid4().hex[:6]}"),
                    command=cmd_data["command"],
                    purpose=cmd_data.get("purpose", ""),
                    tool=cmd_data.get("tool", ""),
                )
            )
        return commands

    async def _execute_commands(
        self, commands: list[ReconCommand]
    ) -> str:
        parts = []
        for cmd in commands:
            logger.info("recon_executing", command_id=cmd.command_id, command=cmd.command)
            result = await self.tool_executor.execute(cmd.command, timeout=30)
            parts.append(
                f"Command [{cmd.command_id}]: {cmd.command}\n"
                f"Purpose: {cmd.purpose}\n"
                f"Exit code: {result.exit_code}\n"
                f"Stdout:\n{truncate_to_tokens(result.stdout, _RECON_CMD_STDOUT_TOKENS)}\n"
                f"Stderr:\n{truncate_to_tokens(result.stderr, _RECON_CMD_STDERR_TOKENS)}\n"
            )
        return "\n---\n".join(parts)

    async def _interpret_results(
        self,
        target_url: str,
        command_results: str,
        graph: APIAssetGraph,
        iteration: int,
    ) -> ReconInterpretation:
        graph_summary = graph.summary()
        budget = prompt_token_budget(
            self.llm_client.config.context_window,
            self.llm_client.config.max_tokens,
        )
        skeleton = recon_interpret_prompt(
            target_url=target_url,
            command_results="",
            graph_summary="",
            iteration=iteration,
            max_iterations=self.config.max_iterations,
        )
        base_tokens = count_tokens(RECON_SYSTEM) + count_tokens(skeleton)
        command_results, graph_summary = allocate_blocks(
            [command_results, graph_summary], max(0, budget - base_tokens)
        )

        prompt = recon_interpret_prompt(
            target_url=target_url,
            command_results=command_results,
            graph_summary=graph_summary,
            iteration=iteration,
            max_iterations=self.config.max_iterations,
        )

        messages = [
            {"role": "system", "content": RECON_SYSTEM},
            {"role": "user", "content": prompt},
        ]

        try:
            return await self.llm_client.generate_json(
                messages, ReconInterpretation, purpose="recon_interpretation"
            )
        except Exception as exc:
            logger.error("recon_interpretation_failed", error=str(exc))
            return ReconInterpretation(continue_recon=False, reasoning=f"Interpretation failed: {exc}")

    @staticmethod
    def _finding_signature(f: ReconFinding) -> str:
        return f"{f.finding_type}::{json.dumps(f.data, sort_keys=True, ensure_ascii=False)}"

    @classmethod
    def _dedup_findings(cls, findings: list[ReconFinding]) -> list[ReconFinding]:
        seen: set[str] = set()
        unique: list[ReconFinding] = []
        for f in findings:
            sig = cls._finding_signature(f)
            if sig in seen:
                continue
            seen.add(sig)
            unique.append(f)
        return unique

    def _process_findings(
        self, interpretation: ReconInterpretation, commands: list[ReconCommand]
    ) -> list[ReconFinding]:
        findings = []
        for f in interpretation.findings:
            raw = f.get("raw_evidence", "")
            if not isinstance(raw, str):
                raw = json.dumps(raw, ensure_ascii=False) if raw not in ({}, [], None) else ""
            data = f.get("data", {})
            if not isinstance(data, dict):
                data = {"value": data}
            findings.append(
                ReconFinding(
                    finding_id=f.get("finding_id", f"finding-{uuid.uuid4().hex[:6]}"),
                    source_command=f.get("source_command", commands[0].command_id if commands else ""),
                    finding_type=f.get("finding_type", "unknown"),
                    data=data,
                    raw_output=raw,
                )
            )
        return findings

    def _apply_graph_updates(
        self, graph: APIAssetGraph, updates: list[dict]
    ) -> None:
        for update in updates:
            action = update.get("action", "")
            try:
                if action == "add_product":
                    self._add_product(graph, update)
                elif action == "add_endpoint":
                    self._add_endpoint(graph, update)
                elif action == "add_parameter":
                    self._add_parameter(graph, update)
                elif action == "add_auth":
                    self._add_auth(graph, update)
                elif action == "add_response":
                    self._add_response(graph, update)
                elif action == "add_weakness":
                    self._add_weakness(graph, update)
                elif action == "add_hypothesis":
                    self._add_hypothesis(graph, update)
                else:
                    logger.warning("unknown_graph_update_action", action=action)
            except Exception as exc:
                logger.warning("graph_update_failed", action=action, error=str(exc))

    def _add_product(self, graph: APIAssetGraph, update: dict) -> None:
        name = str(update.get("name", "")).strip().lower()
        if not name:
            return
        version = str(update.get("version", "")).strip()
        prod_id = f"product:{name}"
        confidence = update.get("confidence", "medium")
        evidence = update.get("evidence", "")

        existing = graph.get_node(prod_id)
        if existing is None:
            graph.add_node(GraphNode(
                node_id=prod_id,
                node_type=NodeType.PRODUCT,
                properties={
                    "name": name,
                    "version": version,
                    "confidence": confidence,
                    "evidence": evidence,
                    "cve_lookup_status": "pending",
                },
            ))
            return

        props = dict(existing.get("properties", {}))
        if version and not props.get("version"):
            props["version"] = version
        if evidence and evidence not in props.get("evidence", ""):
            existing_ev = props.get("evidence", "")
            props["evidence"] = f"{existing_ev}; {evidence}" if existing_ev else evidence
        if confidence == "high":
            props["confidence"] = "high"
        graph.graph.nodes[prod_id]["properties"] = props

    def _add_endpoint(self, graph: APIAssetGraph, update: dict) -> None:
        path = update["path"]
        base_url = update.get("base_url", "")
        ep_id = f"endpoint:{path}"

        if not graph.has_node(ep_id):
            graph.add_node(GraphNode(
                node_id=ep_id,
                node_type=NodeType.ENDPOINT,
                properties={"path": path, "base_url": base_url, "discovered_by": update.get("discovered_by", "")},
            ))

        for method in update.get("methods", []):
            method_id = f"method:{method}:{path}"
            if not graph.has_node(method_id):
                graph.add_node(GraphNode(
                    node_id=method_id,
                    node_type=NodeType.METHOD,
                    properties={"http_method": method, "endpoint_ref": path},
                ))
                graph.add_edge(ep_id, method_id, EdgeType.HAS_METHOD)

    def _add_parameter(self, graph: APIAssetGraph, update: dict) -> None:
        ep_path = update["endpoint_path"]
        method = update["method"]
        name = update["name"]
        method_id = f"method:{method}:{ep_path}"
        param_id = f"param:{name}:{method}:{ep_path}"

        if not graph.has_node(param_id):
            graph.add_node(GraphNode(
                node_id=param_id,
                node_type=NodeType.PARAMETER,
                properties={
                    "name": name,
                    "location": update.get("location", "query"),
                    "param_type": update.get("param_type", "string"),
                },
            ))
            if graph.has_node(method_id):
                graph.add_edge(method_id, param_id, EdgeType.HAS_PARAMETER)

    def _add_auth(self, graph: APIAssetGraph, update: dict) -> None:
        ep_path = update["endpoint_path"]
        method = update["method"]
        auth_type = update.get("auth_type", "unknown")
        method_id = f"method:{method}:{ep_path}"
        auth_id = f"auth:{auth_type}:{method}:{ep_path}"

        if not graph.has_node(auth_id):
            graph.add_node(GraphNode(
                node_id=auth_id,
                node_type=NodeType.AUTH_SCHEME,
                properties={
                    "type": auth_type,
                    "token_location": update.get("location", "header"),
                },
            ))
            if graph.has_node(method_id):
                graph.add_edge(method_id, auth_id, EdgeType.REQUIRES_AUTH)

    def _add_response(self, graph: APIAssetGraph, update: dict) -> None:
        ep_path = update["endpoint_path"]
        method = update["method"]
        status = update.get("status_code", 200)
        method_id = f"method:{method}:{ep_path}"
        resp_id = f"resp:{status}:{method}:{ep_path}"

        if not graph.has_node(resp_id):
            graph.add_node(GraphNode(
                node_id=resp_id,
                node_type=NodeType.RESPONSE,
                properties={
                    "status_code": status,
                    "content_type": update.get("content_type", ""),
                    "body_sample": update.get("body_sample", ""),
                },
            ))
            if graph.has_node(method_id):
                graph.add_edge(method_id, resp_id, EdgeType.PRODUCED_RESPONSE)

    def _add_weakness(self, graph: APIAssetGraph, update: dict) -> None:
        ep_path = update["endpoint_path"]
        method = update["method"]
        wtype = update.get("weakness_type", "unknown")
        method_id = f"method:{method}:{ep_path}"
        weak_id = f"weakness:{wtype}:{method}:{ep_path}"

        if not graph.has_node(weak_id):
            graph.add_node(GraphNode(
                node_id=weak_id,
                node_type=NodeType.WEAKNESS,
                properties={
                    "type": wtype,
                    "confidence": update.get("confidence", "medium"),
                    "evidence": update.get("evidence", ""),
                },
            ))
            if graph.has_node(method_id):
                graph.add_edge(method_id, weak_id, EdgeType.HAS_WEAKNESS)

    def _add_hypothesis(self, graph: APIAssetGraph, update: dict) -> None:
        desc = update.get("description", "")
        hyp_id = f"hypothesis:{uuid.uuid4().hex[:8]}"
        target_ep = update.get("target_endpoint", "")
        target_method = update.get("target_method", "")

        graph.add_node(GraphNode(
            node_id=hyp_id,
            node_type=NodeType.EXPLOIT_HYPOTHESIS,
            properties={
                "description": desc,
                "target_endpoint": target_ep,
                "target_method": target_method,
                "cve_ref": update.get("cve_ref", ""),
            },
        ))

        selectors = [s for s in (target_ep, target_method) if s]
        if selectors:
            for w in graph.get_weaknesses():
                w_id = w.get("node_id", "")
                if any(sel in w_id for sel in selectors):
                    graph.add_edge(hyp_id, w["node_id"], EdgeType.TARGETS)
                    break

    async def _run_dir_enumeration(
        self, target_url: str, graph: APIAssetGraph
    ) -> list[ReconFinding]:
        try:
            enumerator = DirEnumerator(self.config.dir_enum)
            results = await enumerator.enumerate(target_url)
        except Exception as exc:  # noqa: BLE001 — must not crash recon
            logger.warning("dir_enum_failed", error=str(exc))
            return []

        findings: list[ReconFinding] = []
        for r in results:
            ep_id = f"endpoint:{r.path}"
            if not graph.has_node(ep_id):
                graph.add_node(GraphNode(
                    node_id=ep_id,
                    node_type=NodeType.ENDPOINT,
                    properties={
                        "path": r.path,
                        "base_url": target_url,
                        "discovered_by": "dir_enum",
                        "status_code": r.status_code,
                        "content_type": r.content_type,
                    },
                ))
            findings.append(ReconFinding(
                finding_id=f"direnum-{uuid.uuid4().hex[:6]}",
                source_command=f"dir_enum {target_url}",
                finding_type="endpoint",
                data={
                    "path": r.path,
                    "status_code": r.status_code,
                    "content_type": r.content_type,
                    "content_length": r.content_length,
                },
                raw_output=f"{r.status_code} {r.path} ({r.content_type})",
            ))

        logger.info(
            "dir_enum_recon_integrated",
            target=target_url,
            paths_found=len(findings),
        )
        return findings

    async def _fetch_official_cve_context(self, cve_id: str | None) -> str:
        if not cve_id or self.cve_lookup is None:
            return ""
        try:
            detail = await self.cve_lookup.client.get_cve(cve_id)
        except Exception as exc:  # noqa: BLE001 — grounding is best-effort
            logger.warning("official_cve_fetch_failed", cve_id=cve_id, error=str(exc))
            return ""
        if not detail:
            return ""

        title = detail.get("title") or ""
        desc = detail.get("description") or ""
        weaknesses = detail.get("weaknesses") or []
        cwe = ", ".join(w for w in weaknesses if isinstance(w, str)) if isinstance(weaknesses, list) else ""

        parts = [f"Target CVE (public advisory): {cve_id}"]
        if title:
            parts.append(f"Title: {title}")
        if cwe:
            parts.append(f"CWE: {cwe}")
        if desc:
            parts.append(f"Description: {desc}")
        return "\n".join(parts) if len(parts) > 1 else ""

    async def _lookup_new_products(self, graph: APIAssetGraph):
        if self.cve_lookup is None:
            return []

        from src.knowledge.rag_engine import RAGResult

        products = graph.get_products()
        pending = [
            p for p in products
            if p.get("properties", {}).get("cve_lookup_status") == "pending"
        ]
        if not pending:
            return []

        fresh_results: list[RAGResult] = []
        for product in pending:
            props = product.get("properties", {})
            name = props.get("name", "")
            if not name:
                continue

            try:
                cve_hits: list[CVELookupResult] = await self.cve_lookup.lookup_by_product(name)
            except Exception as exc:  # noqa: BLE001 — never let lookup crash recon
                logger.warning(
                    "cve_lookup_failed", product=name, error=str(exc)
                )
                graph.graph.nodes[product["node_id"]]["properties"][
                    "cve_lookup_status"
                ] = "error"
                continue

            if not cve_hits and self.cve_lookup.client.is_throttled():
                logger.info("cve_lookup_deferred_cooldown", product=name)
                continue

            graph.graph.nodes[product["node_id"]]["properties"][
                "cve_lookup_status"
            ] = "done"
            graph.graph.nodes[product["node_id"]]["properties"][
                "cve_lookup_count"
            ] = len(cve_hits)

            if not cve_hits:
                logger.info("cve_lookup_no_results", product=name)
                continue

            documents = [r.to_cve_document() for r in cve_hits]
            self.rag_engine.add_documents(documents)

            for doc, hit in zip(documents, cve_hits, strict=True):
                fresh_results.append(
                    RAGResult(
                        doc_id=doc.doc_id,
                        cve_id=doc.cve_id,
                        content=doc.to_context_string(),
                        score=hit.rank_key()[1] or float(hit.rank_key()[0]),
                        source=doc.source,
                        metadata={
                            "cve_id": doc.cve_id,
                            "severity": hit.severity,
                            "cvss_score": hit.cvss_score,
                            "product_query": name,
                        },
                    )
                )

            logger.info(
                "cve_lookup_results",
                product=name,
                count=len(cve_hits),
                top_cve=cve_hits[0].cve_id if cve_hits else None,
            )

        return fresh_results

    def _summarize_findings(self, findings: list[ReconFinding]) -> str:
        if not findings:
            return ""
        lines = []
        for f in findings[-20:]:
            lines.append(f"[{f.finding_id}] {f.finding_type}: {json.dumps(f.data)}")
        return "\n".join(lines)
