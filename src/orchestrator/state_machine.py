from __future__ import annotations

from datetime import datetime, timezone

import structlog

from src.models.session import FSMState, SessionState

logger = structlog.get_logger(__name__)

TRANSITIONS: dict[FSMState, dict[str, FSMState]] = {
    FSMState.INITIALIZED: {
        "receive_target": FSMState.TARGET_RECEIVED,
        "fail": FSMState.FAILED,
    },
    FSMState.TARGET_RECEIVED: {
        "start_recon": FSMState.RECON_IN_PROGRESS,
        "fail": FSMState.FAILED,
    },
    FSMState.RECON_IN_PROGRESS: {
        "recon_complete": FSMState.PLANNING_IN_PROGRESS,
        "fail": FSMState.FAILED,
    },
    FSMState.PLANNING_IN_PROGRESS: {
        "plan_generated": FSMState.PLAN_VALIDATION,
        "fail": FSMState.FAILED,
    },
    FSMState.PLAN_VALIDATION: {
        "approve": FSMState.EXPLOITATION_IN_PROGRESS,
        "reject_to_recon": FSMState.RECON_IN_PROGRESS,
        "reject_to_planning": FSMState.PLANNING_IN_PROGRESS,
        "fail": FSMState.FAILED,
    },
    FSMState.EXPLOITATION_IN_PROGRESS: {
        "exploit_complete": FSMState.REPORTING,
        "exploit_failed_replan": FSMState.PLANNING_IN_PROGRESS,
        "exploit_failed": FSMState.REPORTING,
        "fail": FSMState.FAILED,
    },
    FSMState.REPORTING: {
        "report_generated": FSMState.COMPLETED,
        "fail": FSMState.FAILED,
    },
    FSMState.COMPLETED: {},
    FSMState.FAILED: {},
}


class InvalidTransitionError(Exception):
    def __init__(self, current_state: FSMState, event: str):
        self.current_state = current_state
        self.event = event
        super().__init__(
            f"Invalid transition: event '{event}' not allowed in state '{current_state.value}'"
        )


class StateMachine:
    def get_valid_events(self, state: FSMState) -> list[str]:
        return list(TRANSITIONS.get(state, {}).keys())

    def can_transition(self, state: FSMState, event: str) -> bool:
        return event in TRANSITIONS.get(state, {})

    def get_next_state(self, current_state: FSMState, event: str) -> FSMState:
        state_transitions = TRANSITIONS.get(current_state, {})
        if event not in state_transitions:
            raise InvalidTransitionError(current_state, event)
        return state_transitions[event]

    def transition(self, session: SessionState, event: str) -> FSMState:
        old_state = session.fsm_state
        new_state = self.get_next_state(old_state, event)
        session.fsm_state = new_state
        session.updated_at = datetime.now(timezone.utc)
        logger.info(
            "state_transition",
            session_id=session.session_id,
            from_state=old_state.value,
            fsm_event=event,
            to_state=new_state.value,
        )
        return new_state
