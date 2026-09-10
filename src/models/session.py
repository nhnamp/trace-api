from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field

from src.models.evidence import ExploitStepResult
from src.models.plan import AttackPlan, ValidationResult
from src.models.recon import ReconFinding
from src.models.target import TargetInfo


class FSMState(str, Enum):
    INITIALIZED = "INITIALIZED"
    TARGET_RECEIVED = "TARGET_RECEIVED"
    RECON_IN_PROGRESS = "RECON_IN_PROGRESS"
    PLANNING_IN_PROGRESS = "PLANNING_IN_PROGRESS"
    PLAN_VALIDATION = "PLAN_VALIDATION"
    EXPLOITATION_IN_PROGRESS = "EXPLOITATION_IN_PROGRESS"
    REPORTING = "REPORTING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class FailureRecord(BaseModel):
    state: FSMState
    error: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    recovery_action: str = ""


class SessionState(BaseModel):
    session_id: str
    target: TargetInfo
    fsm_state: FSMState = FSMState.INITIALIZED
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    recon_results: list[ReconFinding] = []
    api_graph_data: dict = {}
    rag_context: list[dict] = []

    attack_plan: AttackPlan | None = None
    plan_validation: ValidationResult | None = None
    plan_revision_count: int = 0
    exploit_replan_count: int = 0

    exploit_trace: list[ExploitStepResult] = []
    report_path: str | None = None

    failure_history: list[FailureRecord] = []

    def touch(self) -> None:
        self.updated_at = datetime.now(timezone.utc)

    @property
    def is_terminal(self) -> bool:
        return self.fsm_state in (FSMState.COMPLETED, FSMState.FAILED)
