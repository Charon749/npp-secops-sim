from src.models import AlertRecord, JudgementResult
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


def limited_auto_alert():
    return AlertRecord(
        alert_id="A-auto",
        timestamp="2026-05-18T08:00:00",
        source_device="security_tool-log",
        asset_id="ASSET-SCAN-01",
        asset_type="security_tool",
        asset_importance="low",
        event_type="port_scan",
        event_description="simulated threat intel hit",
        user_id="unknown",
        src_ip="198.51.100.61",
        dst_ip="10.10.70.9",
        file_path="",
        process_name="network_monitor",
        behavior_tags=[
            "external_probe",
            "threat_intel_ip_hit",
            "high_confidence_ioc",
            "low_business_impact",
            "auto_containment_candidate",
        ],
        related_alert_ids=[],
        ground_truth_validity=True,
        ground_truth_risk_level="medium",
        ground_truth_event_type="port_scan",
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


def test_limited_auto_containment_is_simulated_only():
    result = WorkflowEngine().process(judgement("medium"), alert=limited_auto_alert())
    assert result.workflow_action == "simulated_block_ip"
    assert result.assigned_role == "automation_orchestrator"
    assert result.need_human_review is False
    assert result.closed_loop_completed is True
    assert any("no real network policy was changed" in item for item in result.audit_log)


def test_high_risk_candidate_still_requires_manual_review():
    result = WorkflowEngine().process(judgement("high"), alert=limited_auto_alert())
    assert result.workflow_action == "mandatory_human_review"
    assert result.need_human_review is True
    assert result.closed_loop_completed is False
