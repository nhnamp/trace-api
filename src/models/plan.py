from __future__ import annotations

from pydantic import BaseModel


class PlanTarget(BaseModel):
    url: str
    cve_id: str | None = None


class VulnerabilityHypothesis(BaseModel):
    type: str
    description: str
    confidence: str = "medium"
    supporting_evidence: list[str] = []


class SuccessCheck(BaseModel):
    expected_status: int | None = None
    must_contain: list[str] = []


class Fallback(BaseModel):
    command: str
    description: str = ""
    success_criteria: str = ""
    success_check: SuccessCheck | None = None


class PlanStep(BaseModel):
    command: str
    description: str
    step_id: str = ""
    expected_result: str = ""
    success_criteria: str = ""
    success_check: SuccessCheck | None = None
    failure_action: str = "try_fallback"
    depends_on: list[str] = []
    is_critical: bool = True
    fallbacks: list[Fallback] = []


class AttackPlan(BaseModel):
    plan_id: str
    target: PlanTarget
    vulnerability_hypothesis: VulnerabilityHypothesis
    preconditions: list[str] = []
    steps: list[PlanStep] = []
    success_criteria: str = ""
    evidence_requirements: list[str] = []


class ValidationResult(BaseModel):
    is_valid: bool
    structural_issues: list[str] = []
    semantic_issues: list[str] = []
    suggestions: list[str] = []
    rejection_reason: str | None = None
