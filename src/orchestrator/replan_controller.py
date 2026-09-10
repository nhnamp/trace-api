from __future__ import annotations

from enum import Enum

import structlog

from src.models.plan import ValidationResult
from src.models.session import SessionState

logger = structlog.get_logger(__name__)


class ReplanAction(str, Enum):
    REJECT_TO_RECON = "reject_to_recon"
    REJECT_TO_PLANNING = "reject_to_planning"
    FAIL = "fail"


class ReplanController:
    def __init__(self, max_replans: int = 3, max_exploit_replans: int = 2) -> None:
        self.max_replans = max_replans
        self.max_exploit_replans = max_exploit_replans

    def should_replan(self, session: SessionState) -> bool:
        return session.plan_revision_count < self.max_replans

    def should_replan_exploit(self, session: SessionState) -> bool:
        return session.exploit_replan_count < self.max_exploit_replans

    def decide(
        self,
        session: SessionState,
        validation: ValidationResult,
    ) -> ReplanAction:
        if session.plan_revision_count >= self.max_replans:
            logger.info(
                "replan_limit_reached",
                session_id=session.session_id,
                revision_count=session.plan_revision_count,
                max_replans=self.max_replans,
            )
            return ReplanAction.FAIL

        needs_more_evidence = self._needs_more_evidence(validation)

        session.plan_revision_count += 1

        if needs_more_evidence:
            logger.info(
                "replan_to_recon",
                session_id=session.session_id,
                revision_count=session.plan_revision_count,
                reason="insufficient_evidence",
            )
            return ReplanAction.REJECT_TO_RECON

        logger.info(
            "replan_to_planning",
            session_id=session.session_id,
            revision_count=session.plan_revision_count,
            reason="plan_quality",
        )
        return ReplanAction.REJECT_TO_PLANNING

    def _needs_more_evidence(self, validation: ValidationResult) -> bool:
        reason = (validation.rejection_reason or "").strip().lower()
        if reason == "insufficient_evidence":
            return True
        if reason == "plan_quality":
            return False

        evidence_keywords = [
            "insufficient evidence",
            "not found in recon",
            "not discovered",
            "no evidence",
            "missing recon",
            "endpoint not found",
            "undiscovered",
        ]
        all_issues = " ".join(
            validation.semantic_issues + validation.structural_issues
        ).lower()
        return any(kw in all_issues for kw in evidence_keywords)
