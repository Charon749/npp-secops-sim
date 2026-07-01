from __future__ import annotations

from typing import Any

from src.agents.webshell_detection_agent import WebShellDetectionAgent
from src.models import AlertRecord, JudgementResult


class AlertJudgementAgent:
    """Explainable rule-scoring alert judgement agent."""

    DEFAULT_WEIGHTS = {
        "asset_importance_score": 0.25,
        "behavior_anomaly_score": 0.25,
        "threat_feature_score": 0.20,
        "correlation_score": 0.20,
        "history_similarity_score": 0.10,
    }

    ASSET_IMPORTANCE_SCORE = {
        "low": 20,
        "medium": 45,
        "high": 75,
        "critical": 95,
    }

    BENIGN_TAGS = {"planned_maintenance", "backup_window", "authorized_internal_scan"}
    THREAT_TAG_WEIGHTS = {
        "suspicious_script": 30,
        "unusual_upload_path": 15,
        "obfuscated_pattern": 25,
        "abnormal_access_path": 20,
        "external_callback_behavior": 25,
        "failed_login_burst": 25,
        "non_working_hours": 18,
        "sensitive_account": 25,
        "multi_port_access": 25,
        "high_connection_frequency": 25,
        "external_probe": 22,
        "sensitive_directory_access": 25,
        "data_exfiltration_indicator": 30,
        "multi_stage_indicator": 30,
        "new_source_ip": 10,
    }

    def __init__(self, weights: dict[str, float] | None = None) -> None:
        self.weights = dict(weights or self.DEFAULT_WEIGHTS)
        self.webshell_agent = WebShellDetectionAgent()

    def judge_alert(
        self, alert: AlertRecord | dict[str, Any], related_alerts: list[AlertRecord | dict[str, Any]] | None = None
    ) -> JudgementResult:
        record = alert if isinstance(alert, AlertRecord) else AlertRecord.from_dict(alert)
        related_records = [
            item if isinstance(item, AlertRecord) else AlertRecord.from_dict(item)
            for item in (related_alerts or [])
        ]

        scores = {
            "asset_importance_score": self._score_asset_importance(record),
            "behavior_anomaly_score": self._score_behavior_anomaly(record),
            "threat_feature_score": self._score_threat_features(record),
            "correlation_score": self._score_correlation(record, related_records),
            "history_similarity_score": self._score_history_similarity(record),
        }
        risk_score = self.calculate_total_score(scores)
        risk_level = self.map_risk_level(risk_score)
        suspected_attack_type = self._suspected_attack_type(record)
        evidence = self._evidence_summary(record, related_records, scores)
        explanation = self._build_explanation(record, scores, risk_score, risk_level, related_records)
        actions = self._recommended_actions(record, risk_level)
        need_human_review = risk_level in {"high", "critical"}
        workflow_action = self.map_workflow_action(risk_level)
        is_valid_alert = self._is_valid_alert(record, risk_score)

        return JudgementResult(
            alert_id=record.alert_id,
            is_valid_alert=is_valid_alert,
            risk_score=round(risk_score, 2),
            risk_level=risk_level,
            suspected_attack_type=suspected_attack_type,
            evidence_summary=evidence,
            explanation=explanation,
            recommended_actions=actions,
            need_human_review=need_human_review,
            workflow_action=workflow_action,
        )

    def calculate_total_score(self, scores: dict[str, float]) -> float:
        def numeric_score(value: Any) -> float:
            if isinstance(value, tuple):
                return float(value[0])
            return float(value)

        return round(
            sum(numeric_score(scores[name]) * float(self.weights[name]) for name in self.DEFAULT_WEIGHTS),
            2,
        )

    @staticmethod
    def map_risk_level(risk_score: float) -> str:
        if risk_score < 40:
            return "low"
        if risk_score < 60:
            return "medium"
        if risk_score < 80:
            return "high"
        return "critical"

    @staticmethod
    def map_workflow_action(risk_level: str) -> str:
        return {
            "low": "archive",
            "medium": "create_ticket",
            "high": "mandatory_human_review",
            "critical": "escalate_incident",
        }[risk_level]

    def _score_asset_importance(self, alert: AlertRecord) -> tuple[float, str]:
        score = self.ASSET_IMPORTANCE_SCORE.get(alert.asset_importance, 20)
        return score, f"asset_importance is {alert.asset_importance}"

    def _score_behavior_anomaly(self, alert: AlertRecord) -> tuple[float, str]:
        tags = set(alert.behavior_tags)
        base = {
            "normal_maintenance": 12,
            "false_positive": 10,
            "abnormal_login": 52,
            "suspicious_web_file": 62,
            "port_scan": 55,
            "abnormal_data_access": 60,
            "outbound_connection": 64,
            "multi_stage_attack": 80,
        }.get(alert.event_type, 20)
        tag_score = sum(self.THREAT_TAG_WEIGHTS.get(tag, 0) for tag in tags)
        benign_penalty = 25 if tags & self.BENIGN_TAGS else 0
        score = max(0, min(100, base + tag_score * 0.65 - benign_penalty))
        if self._is_benign_context(tags):
            score = min(score, 25)
        evidence = self._join_evidence(
            f"event_type is {alert.event_type}",
            f"behavior tags: {', '.join(sorted(tags))}" if tags else "no behavior tags",
            "benign maintenance tag reduces anomaly score" if benign_penalty else "",
        )
        return score, evidence

    def _score_threat_features(self, alert: AlertRecord) -> tuple[float, str]:
        tags = set(alert.behavior_tags)
        if self._is_benign_context(tags) or (
            alert.event_type in {"normal_maintenance", "false_positive"} and tags <= self.BENIGN_TAGS
        ):
            return 8, "benign event type or authorized maintenance context"

        event_base = {
            "suspicious_web_file": 45,
            "abnormal_login": 35,
            "port_scan": 35,
            "abnormal_data_access": 40,
            "outbound_connection": 45,
            "multi_stage_attack": 55,
        }.get(alert.event_type, 15)
        score = event_base + sum(self.THREAT_TAG_WEIGHTS.get(tag, 0) for tag in tags)
        if alert.event_type == "suspicious_web_file":
            webshell_result = self.webshell_agent.analyze(alert)
            score = max(score, webshell_result.webshell_risk_score)
            evidence = "; ".join(webshell_result.evidence)
        else:
            evidence = f"threat-like tags: {', '.join(sorted(tags))}" if tags else "no explicit threat tags"

        if tags & self.BENIGN_TAGS:
            score -= 20
            evidence += "; benign maintenance evidence reduces threat feature score"

        return max(0, min(100, score)), evidence

    def _score_correlation(
        self, alert: AlertRecord, related_alerts: list[AlertRecord]
    ) -> tuple[float, str]:
        explicit_related_count = len(alert.related_alert_ids)
        same_asset_events = {item.event_type for item in related_alerts if item.asset_id == alert.asset_id}
        event_variety = len(same_asset_events | {alert.event_type})

        if "multi_stage_indicator" in set(alert.behavior_tags) or alert.event_type == "multi_stage_attack":
            score = 90
        elif explicit_related_count >= 4 or event_variety >= 4:
            score = 82
        elif explicit_related_count >= 2 or event_variety >= 3:
            score = 65
        elif explicit_related_count == 1 or event_variety == 2:
            score = 42
        else:
            score = 15

        evidence = self._join_evidence(
            f"related_alert_ids count is {explicit_related_count}",
            f"same-asset event variety is {event_variety}",
        )
        return score, evidence

    def _score_history_similarity(self, alert: AlertRecord) -> tuple[float, str]:
        score = {
            "suspicious_web_file": 68,
            "abnormal_login": 60,
            "port_scan": 55,
            "abnormal_data_access": 62,
            "outbound_connection": 64,
            "multi_stage_attack": 78,
            "normal_maintenance": 18,
            "false_positive": 15,
        }.get(alert.event_type, 25)
        if "multi_stage_indicator" in set(alert.behavior_tags):
            score += 12
        return min(100, score), f"similar simulated historical pattern for {alert.event_type}"

    def _evidence_summary(
        self, alert: AlertRecord, related_alerts: list[AlertRecord], scores: dict[str, tuple[float, str]]
    ) -> list[str]:
        summary = [f"涉及 {alert.asset_importance} 重要性资产 {alert.asset_id}"]
        tags = set(alert.behavior_tags)
        if alert.event_type == "suspicious_web_file":
            summary.append("可疑 Web 文件场景仅基于文件元数据和行为标签进行仿真判断")
        if tags:
            summary.append(f"检测到行为标签：{', '.join(sorted(tags))}")
        if alert.related_alert_ids or related_alerts:
            summary.append("存在 related_alert_ids 或同资产告警关联")
        if scores["threat_feature_score"][0] >= 70:
            summary.append("威胁特征评分较高，需要人工结合日志复核")
        return summary

    def _build_explanation(
        self,
        alert: AlertRecord,
        scores: dict[str, tuple[float, str]],
        risk_score: float,
        risk_level: str,
        related_alerts: list[AlertRecord],
    ) -> dict[str, Any]:
        explanation: dict[str, Any] = {}
        for name, (score, evidence) in scores.items():
            weight = self.weights[name]
            explanation[name] = {
                "score": round(float(score), 2),
                "weight": weight,
                "contribution": round(float(score) * weight, 2),
                "evidence": evidence,
            }
        explanation["final_assessment"] = {
            "risk_score": round(risk_score, 2),
            "risk_level": risk_level,
            "reason": self._join_evidence(
                f"weighted score falls into {risk_level} interval",
                f"event_type is {alert.event_type}",
                f"{len(related_alerts)} related alerts used for contextual scoring",
            ),
        }
        return explanation

    def _recommended_actions(self, alert: AlertRecord, risk_level: str) -> list[str]:
        if risk_level == "low":
            return ["自动归档仿真告警", "保留审计日志", "纳入周期性规则复核"]
        if risk_level == "medium":
            return ["生成普通工单", "复核资产、账号和业务窗口", "补充同源告警关联分析"]

        actions = ["进入人工复核", "收集相关日志和资产上下文", "确认后再执行真实处置操作"]
        if alert.event_type == "suspicious_web_file":
            actions.insert(1, "人工复核可疑文件元数据和 Web 访问日志")
        if risk_level == "critical":
            actions.append("触发升级处置流程并由负责人审批")
        return actions

    def _suspected_attack_type(self, alert: AlertRecord) -> str:
        return {
            "abnormal_login": "suspected_account_abuse",
            "suspicious_web_file": "suspected_webshell_metadata_event",
            "port_scan": "reconnaissance_or_probe",
            "abnormal_data_access": "abnormal_data_access",
            "outbound_connection": "suspicious_outbound_connection",
            "multi_stage_attack": "multi_stage_attack_chain",
            "normal_maintenance": "normal_maintenance",
            "false_positive": "benign_or_false_positive",
        }.get(alert.event_type, "unknown")

    def _is_valid_alert(self, alert: AlertRecord, risk_score: float) -> bool:
        if alert.event_type in {"normal_maintenance", "false_positive"} and set(alert.behavior_tags) <= self.BENIGN_TAGS:
            return False
        if self._is_benign_context(set(alert.behavior_tags)):
            return False
        return risk_score >= 40 or bool(set(alert.behavior_tags) - self.BENIGN_TAGS)

    @staticmethod
    def _join_evidence(*items: str) -> str:
        return "; ".join(item for item in items if item)

    def _is_benign_context(self, tags: set[str]) -> bool:
        non_benign = tags - self.BENIGN_TAGS
        return bool(tags & self.BENIGN_TAGS) and non_benign <= {"multi_port_access", "high_connection_frequency"}
