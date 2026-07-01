from __future__ import annotations

from collections import defaultdict, deque
from datetime import timedelta
from typing import Any

from src.models import AlertRecord, IncidentWarning


class EarlyWarningAgent:
    """Aggregates related simulated alerts into incident-level warnings."""

    CHAIN_EVENT_TYPES = {
        "port_scan",
        "abnormal_login",
        "suspicious_web_file",
        "abnormal_data_access",
        "outbound_connection",
        "multi_stage_attack",
    }

    def __init__(self, time_window_minutes: int = 120) -> None:
        self.time_window = timedelta(minutes=time_window_minutes)

    def aggregate(self, alerts: list[AlertRecord | dict[str, Any]]) -> list[IncidentWarning]:
        records = [item if isinstance(item, AlertRecord) else AlertRecord.from_dict(item) for item in alerts]
        if not records:
            return []

        components = self._related_components(records)
        candidate_groups = components + self._same_asset_time_groups(records)
        seen_keys: set[tuple[str, ...]] = set()
        warnings: list[IncidentWarning] = []

        for group in candidate_groups:
            key = tuple(sorted(alert.alert_id for alert in group))
            if len(key) < 3 or key in seen_keys:
                continue
            seen_keys.add(key)
            warning = self._build_warning(group, len(warnings) + 1)
            if warning:
                warnings.append(warning)

        return warnings

    def _related_components(self, records: list[AlertRecord]) -> list[list[AlertRecord]]:
        by_id = {alert.alert_id: alert for alert in records}
        adjacency: dict[str, set[str]] = defaultdict(set)
        for alert in records:
            for related_id in alert.related_alert_ids:
                if related_id in by_id:
                    adjacency[alert.alert_id].add(related_id)
                    adjacency[related_id].add(alert.alert_id)

        visited: set[str] = set()
        components: list[list[AlertRecord]] = []
        for alert in records:
            if alert.alert_id in visited or alert.alert_id not in adjacency:
                continue
            queue: deque[str] = deque([alert.alert_id])
            visited.add(alert.alert_id)
            component: list[AlertRecord] = []
            while queue:
                alert_id = queue.popleft()
                component.append(by_id[alert_id])
                for neighbor in adjacency[alert_id]:
                    if neighbor not in visited:
                        visited.add(neighbor)
                        queue.append(neighbor)
            components.append(component)
        return components

    def _same_asset_time_groups(self, records: list[AlertRecord]) -> list[list[AlertRecord]]:
        groups: list[list[AlertRecord]] = []
        by_asset: dict[str, list[AlertRecord]] = defaultdict(list)
        for alert in records:
            by_asset[alert.asset_id].append(alert)

        for asset_alerts in by_asset.values():
            ordered = sorted(asset_alerts, key=lambda item: item.parsed_timestamp())
            for index, anchor in enumerate(ordered):
                window = [
                    item
                    for item in ordered[index:]
                    if item.parsed_timestamp() - anchor.parsed_timestamp() <= self.time_window
                ]
                if len(window) >= 3:
                    groups.append(window)
                    break
        return groups

    def _build_warning(self, group: list[AlertRecord], index: int) -> IncidentWarning | None:
        event_types = {alert.event_type for alert in group}
        tags = {tag for alert in group for tag in alert.behavior_tags}
        chain_types = event_types & self.CHAIN_EVENT_TYPES
        is_chain = len(chain_types) >= 3 or "multi_stage_indicator" in tags
        if not is_chain:
            return None

        high_importance = any(alert.asset_importance in {"high", "critical"} for alert in group)
        if len(chain_types) >= 5 or "multi_stage_indicator" in tags:
            risk_level = "critical" if high_importance else "high"
        elif len(chain_types) >= 3:
            risk_level = "high"
        else:
            risk_level = "medium"

        ordered = sorted(group, key=lambda item: item.parsed_timestamp())
        related_ids = [alert.alert_id for alert in ordered]
        summary = self._attack_chain_summary(event_types)
        evidence = [
            f"聚合告警数量：{len(group)}",
            f"涉及资产：{', '.join(sorted({alert.asset_id for alert in group}))}",
            f"事件类型序列：{', '.join(alert.event_type for alert in ordered)}",
            f"行为标签：{', '.join(sorted(tags))}",
        ]
        action = "escalate_incident" if risk_level == "critical" else "mandatory_human_review"
        report = (
            f"事件 {index:03d} 聚合了 {len(group)} 条相关告警，风险等级为 {risk_level}。"
            f"{summary} 本平台仅输出人工复核与流程升级建议，不执行真实网络处置。"
        )

        return IncidentWarning(
            incident_id=f"INC{index:04d}",
            related_alert_ids=related_ids,
            incident_type="multi_stage_attack_chain",
            incident_risk_level=risk_level,
            attack_chain_summary=summary,
            evidence_summary=evidence,
            recommended_workflow_action=action,
            warning_report=report,
        )

    def _attack_chain_summary(self, event_types: set[str]) -> str:
        phrases = []
        if "port_scan" in event_types:
            phrases.append("外部探测")
        if "abnormal_login" in event_types:
            phrases.append("异常登录尝试")
        if "suspicious_web_file" in event_types:
            phrases.append("可疑文件上传")
        if "abnormal_data_access" in event_types:
            phrases.append("敏感目录或数据访问")
        if "outbound_connection" in event_types:
            phrases.append("对外连接行为")
        chain_text = "、".join(phrases) or "多源异常行为"
        return (
            f"该事件疑似由{chain_text}构成，具备多阶段攻击链特征，"
            "建议触发人工复核和升级处置流程。"
        )
