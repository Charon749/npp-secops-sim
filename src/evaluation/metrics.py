from __future__ import annotations

from typing import Any

from src.models import AlertRecord, JudgementResult, WorkflowResult


def expected_workflow_action(risk_level: str) -> str:
    return {
        "low": "archive",
        "medium": "create_ticket",
        "high": "mandatory_human_review",
        "critical": "escalate_incident",
    }[risk_level]


def compute_metrics(
    alerts: list[AlertRecord | dict[str, Any]],
    judgements: list[JudgementResult | dict[str, Any]],
    workflows: list[WorkflowResult | dict[str, Any]],
) -> dict[str, float]:
    alert_rows = [_as_dict(item) for item in alerts]
    judgement_rows = [_as_dict(item) for item in judgements]
    workflow_rows = [_as_dict(item) for item in workflows]

    by_judgement = {row["alert_id"]: row for row in judgement_rows}
    by_workflow = {row["alert_id"]: row for row in workflow_rows}

    total_alerts = len(alert_rows)
    true_positive = false_positive = true_negative = false_negative = 0
    risk_match = 0
    workflow_match = 0
    judgement_times: list[float] = []
    high_risk_total = 0
    high_risk_reviewed = 0
    closed_loop_count = 0

    for alert in alert_rows:
        alert_id = alert["alert_id"]
        judgement = by_judgement[alert_id]
        workflow = by_workflow[alert_id]

        gt_valid = _as_bool(alert.get("ground_truth_validity"))
        predicted_valid = _as_bool(judgement.get("is_valid_alert"))
        if gt_valid and predicted_valid:
            true_positive += 1
        elif not gt_valid and predicted_valid:
            false_positive += 1
        elif not gt_valid and not predicted_valid:
            true_negative += 1
        elif gt_valid and not predicted_valid:
            false_negative += 1

        if judgement["risk_level"] == alert.get("ground_truth_risk_level"):
            risk_match += 1

        expected_action = expected_workflow_action(str(alert.get("ground_truth_risk_level", "low")))
        if workflow["workflow_action"] == expected_action:
            workflow_match += 1

        judgement_times.append(float(judgement.get("judgement_time_ms") or 0.0))

        if judgement["risk_level"] in {"high", "critical"}:
            high_risk_total += 1
            if _as_bool(workflow.get("need_human_review")):
                high_risk_reviewed += 1

        if _as_bool(workflow.get("closed_loop_completed")):
            closed_loop_count += 1

    return {
        "total_alerts": float(total_alerts),
        "valid_alert_detection_rate": round(_safe_div(true_positive, true_positive + false_negative), 4),
        "false_positive_rate": round(_safe_div(false_positive, false_positive + true_negative), 4),
        "false_negative_rate": round(_safe_div(false_negative, true_positive + false_negative), 4),
        "risk_level_consistency_rate": round(_safe_div(risk_match, total_alerts), 4),
        "average_judgement_time_ms": round(_safe_div(sum(judgement_times), len(judgement_times)), 4),
        "workflow_trigger_accuracy": round(_safe_div(workflow_match, total_alerts), 4),
        "high_risk_human_review_rate": round(_safe_div(high_risk_reviewed, high_risk_total), 4),
        "closed_loop_rate": round(_safe_div(closed_loop_count, total_alerts), 4),
    }


def _as_dict(value: Any) -> dict[str, Any]:
    if hasattr(value, "__dict__"):
        return dict(value.__dict__)
    return dict(value)


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.lower() in {"true", "1", "yes", "y"}
    return False


def _safe_div(numerator: float, denominator: float) -> float:
    return 0.0 if denominator == 0 else numerator / denominator
