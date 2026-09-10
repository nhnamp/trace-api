from __future__ import annotations

import copy
from pathlib import Path

import yaml
from pydantic import BaseModel, model_validator


class LLMProviderConfig(BaseModel):
    provider: str | None = None
    model: str | None = None
    temperature: float = 0.3
    max_tokens: int = 4096
    context_window: int | None = None
    api_key: str | None = None
    api_base: str | None = None
    extra_headers: dict[str, str] = {}
    json_response_format: bool | None = None
    num_retries: int | None = None
    stream: bool | None = None
    extra_body: dict = {}


class LLMConfig(BaseModel):
    provider: str = "openai"
    model: str = "gpt-5"
    api_key: str | None = None
    api_base: str | None = None
    context_window: int = 8192
    extra_headers: dict[str, str] = {}
    json_response_format: bool = True
    num_retries: int = 0
    stream: bool = True
    extra_body: dict = {}

    planning: LLMProviderConfig = LLMProviderConfig()
    verifier: LLMProviderConfig = LLMProviderConfig(temperature=0.1)
    exploiting: LLMProviderConfig = LLMProviderConfig(temperature=0.2)
    reporting: LLMProviderConfig = LLMProviderConfig(temperature=0.4, max_tokens=16384)

    _AGENT_FIELDS: list[str] = ["planning", "verifier", "exploiting", "reporting"]

    @model_validator(mode="after")
    def inherit_top_level_defaults(self) -> LLMConfig:
        for name in self._AGENT_FIELDS:
            cfg: LLMProviderConfig = getattr(self, name)
            if cfg.provider is None:
                cfg.provider = self.provider
            if cfg.model is None:
                cfg.model = self.model
            if cfg.context_window is None:
                cfg.context_window = self.context_window
            if cfg.json_response_format is None:
                cfg.json_response_format = self.json_response_format
            if cfg.num_retries is None:
                cfg.num_retries = self.num_retries
            if cfg.stream is None:
                cfg.stream = self.stream
            if not cfg.extra_headers and self.extra_headers:
                cfg.extra_headers = dict(self.extra_headers)
            if not cfg.extra_body and self.extra_body:
                cfg.extra_body = copy.deepcopy(self.extra_body)
            if cfg.api_base is None and self.api_base is not None:
                cfg.api_base = self.api_base
            cfg.api_key = cfg.api_key or self.api_key
        return self


class KnowledgeConfig(BaseModel):
    chroma_persist_dir: str = "knowledge_base/chroma"
    bm25_index_dir: str = "knowledge_base/bm25_index"
    collection_name: str = "cve_knowledge"
    top_k: int = 10
    rrf_k: int = 60


class DirEnumConfig(BaseModel):
    enabled: bool = True
    wordlist_path: str | None = None
    concurrency: int = 20
    timeout_seconds: int = 5
    max_paths: int = 300
    max_findings: int = 40
    interesting_status_codes: list[int] = [
        200, 201, 202, 204, 301, 302, 307, 308, 401, 403, 405, 500, 502, 503,
    ]
    bypass_probe_enabled: bool = True
    bypass_max_probes: int = 80
    bypass_max_bases: int = 2


class ReconConfig(BaseModel):
    max_iterations: int = 10
    max_commands_per_iteration: int = 3
    dir_enum: DirEnumConfig = DirEnumConfig()


class CVELookupConfig(BaseModel):
    enabled: bool = True
    base_url: str = "https://app.opencve.io/api"
    timeout_seconds: int = 15
    max_alt_names: int = 5
    max_cves_per_product: int = 5
    fetch_detail_for_top_k: int = 3
    use_llm_alt_names: bool = True
    token: str | None = None

    def resolved_token(self) -> str | None:
        return self.token


class SandboxConfig(BaseModel):
    image: str = "trace-api-executor:latest"
    container_name: str = "trace-api-sandbox"
    network_mode: str = "host"
    extra_volumes: list[str] = []
    extra_env: dict[str, str] = {}


class ExecutionConfig(BaseModel):
    mode: str = "host"
    timeout_seconds: int = 60
    max_timeout_seconds: int = 300
    max_output_bytes: int = 102400
    sandbox: SandboxConfig = SandboxConfig()


class SessionConfig(BaseModel):
    session_dir: str = "sessions"


class OrchestratorConfig(BaseModel):
    max_replans: int = 3
    max_exploit_replans: int = 2
    max_fallbacks_per_step: int = 3
    max_generation_retries: int = 2
    plan_fallbacks_enabled: bool = True


class ReportConfig(BaseModel):
    output_dir: str = "reports"
    include_raw_logs: bool = True
    include_remediation: bool = True


class LoggingConfig(BaseModel):
    level: str = "INFO"
    json_output: bool = False
    llm_log_dir: str = "sessions"


class SystemConfig(BaseModel):
    llm: LLMConfig = LLMConfig()
    execution: ExecutionConfig = ExecutionConfig()
    session: SessionConfig = SessionConfig()
    orchestrator: OrchestratorConfig = OrchestratorConfig()
    logging: LoggingConfig = LoggingConfig()
    knowledge: KnowledgeConfig = KnowledgeConfig()
    recon: ReconConfig = ReconConfig()
    cve_lookup: CVELookupConfig = CVELookupConfig()
    report: ReportConfig = ReportConfig()

    @classmethod
    def from_yaml(cls, path: str | Path) -> SystemConfig:
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        return cls(**data)

    @classmethod
    def default(cls) -> SystemConfig:
        return cls()
