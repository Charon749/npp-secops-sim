from src.models import JudgementResult
from src.workflow.workflow_engine import WorkflowEngine


def judgement(risk_level):
    return JudgementResult(
        alert_id=f"A-{risk_level}",
        is_valid_alert=risk_level != "low",
        risk_score={"low": 20, "medium": 50, "high": 70, "critical": 90}[risk_level],
        risk_level=risk_level,
        suspected_attack_type="test",
        evidence_summary=["evidence"],
        explanation={},
        recommended_actions=["action"],
        need_human_review=risk_level in {"high", "critical"},
        workflow_action="",
    )


def test_low_risk_is_archived_with_audit_log():
    result = WorkflowEngine().process(judgement("low"))
    assert result.workflow_action == "archive"
    assert result.closed_loop_completed is True
    assert result.audit_log


def test_high_risk_requires_mandatory_human_review():
    result = WorkflowEngine().process(judgement("high"))
    assert result.workflow_action == "mandatory_human_review"
    assert result.need_human_review is True
    assert result.closed_loop_completed is False


def test_critical_risk_triggers_escalation():
    result = WorkflowEngine().process(judgement("critical"))
    assert result.workflow_action == "escalate_incident"
    assert result.assigned_role == "incident_commander"
    assert result.need_human_review is True
    assert result.closed_loop_completed is False
