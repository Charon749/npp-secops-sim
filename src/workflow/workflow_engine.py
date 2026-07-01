from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from src.models import JudgementResult, WorkflowResult


class WorkflowEngine:
    """Offline workflow simulator.

    High and critical events only create review/escalation records. The engine
    never performs real blocking, deletion, isolation, or network operations.
    """

    ACTIONS = {
        "low": ("archive", "security_auditor", "archived", False, True),
        "medium": ("create_ticket", "soc_operator", "ticket_opened", False, False),
        "high": ("mandatory_human_review", "security_analyst", "pending_human_review", True, False),
        "critical": ("escalate_incident", "incident_commander", "escalated", True, False),
    }

    def process(self, judgement: JudgementResult | dict[str, Any]) -> WorkflowResult:
        payload = judgement if isinstance(judgement, dict) else judgement.__dict__
        alert_id = str(payload["alert_id"])
        risk_level = str(payload["risk_level"])
        action, role, status, need_human_review, closed = self.ACTIONS[risk_level]
        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")

        audit_log = [
            f"{timestamp} received judgement for alert {alert_id}",
            f"{timestamp} risk_level={risk_level}, workflow_action={action}",
            f"{timestamp} assigned_role={role}, status={status}",
        ]
        if risk_level in {"high", "critical"}:
            audit_log.append(f"{timestamp} high-risk event is not auto-closed and requires manual review")
        if risk_level == "low":
            audit_log.append(f"{timestamp} low-risk alert archived with audit evidence retained")

        return WorkflowResult(
            alert_id=alert_id,
            workflow_action=action,
            assigned_role=role,
            status=status,
            audit_log=audit_log,
            need_human_review=need_human_review,
            closed_loop_completed=closed,
        )
