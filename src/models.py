from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime
from typing import Any


ASSET_IMPORTANCE_LEVELS = ("low", "medium", "high", "critical")
EVENT_TYPES = (
    "abnormal_login",
    "suspicious_web_file",
    "port_scan",
    "abnormal_data_access",
    "outbound_connection",
    "normal_maintenance",
    "false_positive",
    "multi_stage_attack",
)
RISK_LEVELS = ("low", "medium", "high", "critical")


def parse_list(value: Any) -> list[str]:
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, tuple):
        return [str(item) for item in value]
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return []
        if stripped.startswith("[") and stripped.endswith("]"):
            import json

            loaded = json.loads(stripped)
            return [str(item) for item in loaded]
        return [item.strip() for item in stripped.split(";") if item.strip()]
    return [str(value)]


def parse_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1", "yes", "y"}
    return False


def to_plain_dict(value: Any) -> dict[str, Any]:
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, dict):
        return value
    raise TypeError(f"Unsupported value type: {type(value)!r}")


@dataclass
class AlertRecord:
    alert_id: str
    timestamp: str
    source_device: str
    asset_id: str
    asset_type: str
    asset_importance: str
    event_type: str
    event_description: str
    user_id: str
    src_ip: str
    dst_ip: str
    file_path: str = ""
    process_name: str = ""
    behavior_tags: list[str] = field(default_factory=list)
    related_alert_ids: list[str] = field(default_factory=list)
    ground_truth_validity: bool = False
    ground_truth_risk_level: str = "low"
    ground_truth_event_type: str = "false_positive"

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "AlertRecord":
        data = dict(payload)
        data["behavior_tags"] = parse_list(data.get("behavior_tags"))
        data["related_alert_ids"] = parse_list(data.get("related_alert_ids"))
        data["ground_truth_validity"] = parse_bool(data.get("ground_truth_validity"))
        return cls(**data)

    def parsed_timestamp(self) -> datetime:
        return datetime.fromisoformat(self.timestamp.replace("Z", "+00:00"))


@dataclass
class JudgementResult:
    alert_id: str
    is_valid_alert: bool
    risk_score: float
    risk_level: str
    suspected_attack_type: str
    evidence_summary: list[str]
    explanation: dict[str, Any]
    recommended_actions: list[str]
    need_human_review: bool
    workflow_action: str
    judgement_time_ms: float = 0.0


@dataclass
class WebShellAnalysis:
    webshell_risk_score: float
    is_suspicious_webshell: bool
    evidence: list[str]
    recommended_actions: list[str]


@dataclass
class IncidentWarning:
    incident_id: str
    related_alert_ids: list[str]
    incident_type: str
    incident_risk_level: str
    attack_chain_summary: str
    evidence_summary: list[str]
    recommended_workflow_action: str
    warning_report: str


@dataclass
class WorkflowResult:
    alert_id: str
    workflow_action: str
    assigned_role: str
    status: str
    audit_log: list[str]
    need_human_review: bool
    closed_loop_completed: bool
