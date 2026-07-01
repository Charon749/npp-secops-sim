from __future__ import annotations

from typing import Any

from src.models import parse_list


DEFAULT_WORKFLOW_ACTIONS = {
    "low": "archive",
    "medium": "create_ticket",
    "high": "mandatory_human_review",
    "critical": "escalate_incident",
}

AUTO_CONTAINMENT_REQUIRED_TAGS = {
    "threat_intel_ip_hit",
    "high_confidence_ioc",
    "low_business_impact",
    "auto_containment_candidate",
}

AUTO_CONTAINMENT_EVENT_TYPES = {"port_scan", "outbound_connection"}
AUTO_CONTAINMENT_ASSET_IMPORTANCE = {"low", "medium"}

AUTO_CONTAINMENT_BLOCKING_TAGS = {
    "multi_stage_indicator",
    "suspicious_script",
    "unusual_upload_path",
    "obfuscated_pattern",
    "abnormal_access_path",
    "sensitive_directory_access",
    "data_exfiltration_indicator",
}


def workflow_action_for_alert(
    risk_level: str,
    alert: Any | None = None,
    risk_score: float | None = None,
) -> str:
    """Return the workflow action under offline simulation safety constraints."""
    if is_limited_auto_containment_candidate(alert, risk_level, risk_score):
        return "simulated_block_ip"
    return DEFAULT_WORKFLOW_ACTIONS[str(risk_level)]


def is_limited_auto_containment_candidate(
    alert: Any | None,
    risk_level: str,
    risk_score: float | None = None,
) -> bool:
    """Allow only narrow, reversible, audit-only simulated IP containment.

    This function never performs a real blocking action. It only marks a
    workflow record as eligible for offline simulated containment.
    """
    if alert is None or str(risk_level) != "medium":
        return False
    if risk_score is not None and float(risk_score) >= 60:
        return False

    tags = set(parse_list(_get(alert, "behavior_tags")))
    if not AUTO_CONTAINMENT_REQUIRED_TAGS <= tags:
        return False
    if tags & AUTO_CONTAINMENT_BLOCKING_TAGS:
        return False
    if parse_list(_get(alert, "related_alert_ids")):
        return False

    event_type = str(_get(alert, "event_type"))
    asset_importance = str(_get(alert, "asset_importance"))
    return (
        event_type in AUTO_CONTAINMENT_EVENT_TYPES
        and asset_importance in AUTO_CONTAINMENT_ASSET_IMPORTANCE
    )


def _get(source: Any, field_name: str) -> Any:
    if isinstance(source, dict):
        return source.get(field_name)
    return getattr(source, field_name, None)
