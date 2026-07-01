from pathlib import Path

from src.evaluation.metrics import compute_metrics
from src.models import AlertRecord, IncidentWarning, JudgementResult, WorkflowResult
from src.reporting.report_generator import generate_outputs


def alert(alert_id, gt_valid, gt_risk):
    return AlertRecord(
        alert_id=alert_id,
        timestamp="2026-05-18T08:00:00",
        source_device="test-log",
        asset_id="ASSET-TEST",
        asset_type="test_asset",
        asset_importance="high",
        event_type="abnormal_login" if gt_valid else "false_positive",
        event_description="test",
        user_id="tester",
        src_ip="192.0.2.1",
        dst_ip="10.0.0.1",
        file_path="",
        process_name="test",
        behavior_tags=["failed_login_burst"] if gt_valid else ["planned_maintenance"],
        related_alert_ids=[],
        ground_truth_validity=gt_valid,
        ground_truth_risk_level=gt_risk,
        ground_truth_event_type="abnormal_login" if gt_valid else "false_positive",
    )


def judgement(alert_id, pred_valid, risk_level, risk_score):
    return JudgementResult(
        alert_id=alert_id,
        is_valid_alert=pred_valid,
        risk_score=risk_score,
        risk_level=risk_level,
        suspected_attack_type="test",
        evidence_summary=["evidence"],
        explanation={
            "asset_importance_score": {"score": 80, "weight": 0.25, "contribution": 20, "evidence": "asset"},
            "behavior_anomaly_score": {"score": 80, "weight": 0.25, "contribution": 20, "evidence": "behavior"},
            "threat_feature_score": {"score": 80, "weight": 0.2, "contribution": 16, "evidence": "threat"},
            "correlation_score": {"score": 40, "weight": 0.2, "contribution": 8, "evidence": "correlation"},
            "history_similarity_score": {"score": 50, "weight": 0.1, "contribution": 5, "evidence": "history"},
            "final_assessment": {"risk_score": risk_score, "risk_level": risk_level, "reason": "test"},
        },
        recommended_actions=["action"],
        need_human_review=risk_level in {"high", "critical"},
        workflow_action={
            "low": "archive",
            "medium": "create_ticket",
            "high": "mandatory_human_review",
            "critical": "escalate_incident",
        }[risk_level],
        judgement_time_ms=1.0,
    )


def workflow(alert_id, risk_level):
    return WorkflowResult(
        alert_id=alert_id,
        workflow_action={
            "low": "archive",
            "medium": "create_ticket",
            "high": "mandatory_human_review",
            "critical": "escalate_incident",
        }[risk_level],
        assigned_role="tester",
        status="done",
        audit_log=["audit"],
        need_human_review=risk_level in {"high", "critical"},
        closed_loop_completed=risk_level == "low",
    )


def test_metrics_are_computed_from_ground_truth():
    alerts = [
        alert("A1", True, "high"),
        alert("A2", False, "low"),
        alert("A3", True, "medium"),
    ]
    judgements = [
        judgement("A1", True, "high", 70),
        judgement("A2", False, "low", 20),
        judgement("A3", False, "low", 25),
    ]
    workflows = [workflow("A1", "high"), workflow("A2", "low"), workflow("A3", "low")]

    metrics = compute_metrics(alerts, judgements, workflows)

    assert metrics["total_alerts"] == 3.0
    assert metrics["valid_alert_detection_rate"] == 0.5
    assert metrics["false_positive_rate"] == 0.0
    assert metrics["false_negative_rate"] == 0.5
    assert metrics["risk_level_consistency_rate"] == 0.6667
    assert metrics["workflow_trigger_accuracy"] == 0.6667
    assert metrics["high_risk_human_review_rate"] == 1.0


def test_report_files_are_generated(tmp_path: Path):
    alerts = [alert("A1", True, "high")]
    judgements = [judgement("A1", True, "high", 70)]
    workflows = [workflow("A1", "high")]
    incidents = [
        IncidentWarning(
            incident_id="INC0001",
            related_alert_ids=["A1"],
            incident_type="multi_stage_attack_chain",
            incident_risk_level="high",
            attack_chain_summary="test chain",
            evidence_summary=["evidence"],
            recommended_workflow_action="mandatory_human_review",
            warning_report="report",
        )
    ]
    results_path, report_path = generate_outputs(
        alerts,
        judgements,
        workflows,
        {"total_alerts": 1.0, "workflow_trigger_accuracy": 1.0},
        incidents,
        tmp_path,
    )
    assert results_path.exists()
    assert report_path.exists()
    assert "局限性说明" in report_path.read_text(encoding="utf-8")
