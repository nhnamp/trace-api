from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, Field

from src.models.evidence import ExploitStepResult
from src.models.plan import AttackPlan, ValidationResult
from src.models.recon import ReconFinding
from src.models.session import FailureRecord, FSMState
from src.models.target import TargetInfo


class ReportInput(BaseModel):
    session_id: str
    target: TargetInfo
    fsm_state: FSMState = FSMState.COMPLETED
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    recon_results: list[ReconFinding] = []
    rag_context: list[dict] = []
    api_graph_data: dict = {}
    attack_plan: AttackPlan | None = None
    plan_validation: ValidationResult | None = None
    plan_revision_count: int = 0
    exploit_trace: list[ExploitStepResult] = []
    failure_history: list[FailureRecord] = []

    @classmethod
    def from_session(cls, session_data: dict) -> ReportInput:
        return cls(**session_data)


class ReportOutput(BaseModel):
    report_path: str
    summary: str
