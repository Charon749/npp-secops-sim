from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from src.models import AlertRecord, JudgementResult, WorkflowResult
from src.workflow.policy import workflow_action_for_alert


class WorkflowEngine:
    """Offline workflow simulator.

    High and critical events only create review/escalation records. Limited
    auto-containment is audit-only simulation and never performs real blocking,
    deletion, isolation, or network operations.
    """

    ACTIONS = {
        "low": ("archive", "security_auditor", "archived", False, True),
        "medium": ("create_ticket", "soc_operator", "ticket_opened", False, False),
        "high": ("mandatory_human_review", "security_analyst", "pending_human_review", True, False),
        "critical": ("escalate_incident", "incident_commander", "escalated", True, False),
    }
    SIMULATED_AUTO_ACTION = (
        "simulated_block_ip",
        "automation_orchestrator",
        "simulated_blocked",
        False,
        True,
    )

    def process(
        self,
        judgement: JudgementResult | dict[str, Any],
        alert: AlertRecord | dict[str, Any] | None = None,
    ) -> WorkflowResult:
        payload = judgement if isinstance(judgement, dict) else judgement.__dict__
        alert_id = str(payload["alert_id"])
        risk_level = str(payload["risk_level"])
        selected_action = workflow_action_for_alert(
            risk_level,
            alert=alert,
            risk_score=float(payload.get("risk_score") or 0.0),
        )
        if selected_action == "simulated_block_ip":
            action, role, status, need_human_review, closed = self.SIMULATED_AUTO_ACTION
        else:
            action, role, status, need_human_review, closed = self.ACTIONS[risk_level]
        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")

        audit_log = [
            f"{timestamp} received judgement for alert {alert_id}",
            f"{timestamp} risk_level={risk_level}, workflow_action={action}",
            f"{timestamp} assigned_role={role}, status={status}",
        ]
        if action == "simulated_block_ip":
            audit_log.extend(
                [
                    f"{timestamp} matched limited auto-containment policy: high-confidence IOC, low business impact, non-critical asset",
                    f"{timestamp} simulated temporary IP block recorded for offline experiment only; no real network policy was changed",
                    f"{timestamp} simulated action is reversible and retained for audit review",
                ]
            )
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
