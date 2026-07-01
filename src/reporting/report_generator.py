from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any

from src.models import AlertRecord, IncidentWarning, JudgementResult, WorkflowResult
from src.utils.display_mapping import (
    get_asset_importance_label,
    get_event_type_label,
    get_risk_level_label,
    get_score_dimension_label,
    get_workflow_action_label,
    localize_metrics,
    translate_text,
    translate_value_by_field,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
OUTPUT_DIR = PROJECT_ROOT / "outputs"


def generate_outputs(
    alerts: list[AlertRecord],
    judgements: list[JudgementResult],
    workflows: list[WorkflowResult],
    metrics: dict[str, float],
    incidents: list[IncidentWarning],
    output_dir: Path | None = None,
) -> tuple[Path, Path]:
    target_dir = output_dir or OUTPUT_DIR
    target_dir.mkdir(parents=True, exist_ok=True)
    results_path = target_dir / "simulation_results.csv"
    report_path = target_dir / "evaluation_report.md"
    write_simulation_results(alerts, judgements, workflows, results_path)
    write_markdown_report(alerts, judgements, workflows, metrics, incidents, report_path)
    return results_path, report_path


def write_simulation_results(
    alerts: list[AlertRecord],
    judgements: list[JudgementResult],
    workflows: list[WorkflowResult],
    output_path: Path,
) -> None:
    judgement_map = {item.alert_id: item for item in judgements}
    workflow_map = {item.alert_id: item for item in workflows}

    fieldnames = [
        "alert_id",
        "timestamp",
        "asset_id",
        "asset_type",
        "asset_importance",
        "event_type",
        "behavior_tags",
        "ground_truth_validity",
        "ground_truth_risk_level",
        "is_valid_alert",
        "risk_score",
        "risk_level",
        "suspected_attack_type",
        "evidence_summary",
        "explanation",
        "recommended_actions",
        "need_human_review",
        "workflow_action",
        "assigned_role",
        "status",
        "audit_log",
        "closed_loop_completed",
        "judgement_time_ms",
    ]
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for alert in alerts:
            judgement = judgement_map[alert.alert_id]
            workflow = workflow_map[alert.alert_id]
            writer.writerow(
                {
                    "alert_id": alert.alert_id,
                    "timestamp": alert.timestamp,
                    "asset_id": alert.asset_id,
                    "asset_type": alert.asset_type,
                    "asset_importance": alert.asset_importance,
                    "event_type": alert.event_type,
                    "behavior_tags": _json(alert.behavior_tags),
                    "ground_truth_validity": alert.ground_truth_validity,
                    "ground_truth_risk_level": alert.ground_truth_risk_level,
                    "is_valid_alert": judgement.is_valid_alert,
                    "risk_score": judgement.risk_score,
                    "risk_level": judgement.risk_level,
                    "suspected_attack_type": judgement.suspected_attack_type,
                    "evidence_summary": _json(judgement.evidence_summary),
                    "explanation": _json(judgement.explanation),
                    "recommended_actions": _json(judgement.recommended_actions),
                    "need_human_review": workflow.need_human_review,
                    "workflow_action": workflow.workflow_action,
                    "assigned_role": workflow.assigned_role,
                    "status": workflow.status,
                    "audit_log": _json(workflow.audit_log),
                    "closed_loop_completed": workflow.closed_loop_completed,
                    "judgement_time_ms": judgement.judgement_time_ms,
                }
            )


def write_markdown_report(
    alerts: list[AlertRecord],
    judgements: list[JudgementResult],
    workflows: list[WorkflowResult],
    metrics: dict[str, float],
    incidents: list[IncidentWarning],
    output_path: Path,
) -> None:
    scenario_counts = Counter(get_event_type_label(alert.event_type) for alert in alerts)
    workflow_counts = Counter(get_workflow_action_label(item.workflow_action) for item in workflows)
    simulated_block_count = sum(item.workflow_action == "simulated_block_ip" for item in workflows)
    risk_counts = Counter(get_risk_level_label(item.risk_level) for item in judgements)
    top_cases = sorted(judgements, key=lambda item: item.risk_score, reverse=True)[:3]
    workflow_map = {item.alert_id: item for item in workflows}
    alert_map = {item.alert_id: item for item in alerts}

    lines = [
        "# 核电厂管理网络告警研判智能体仿真评估报告",
        "",
        "## 一、项目简介",
        "",
        "本项目用于离线验证“模拟安全告警输入 -> 可解释风险评分 -> 工作流触发 -> 指标统计 -> 报告输出”的最小闭环，服务于硕士论文第四章的仿真平台构建与验证分析。",
        "",
        "## 二、仿真边界说明",
        "",
        "- 本项目只使用模拟数据或脱敏化结构字段，不连接真实核电厂管理网络。",
        "- 本项目不生成真实攻击代码、不生成真实WebShell、不执行扫描、利用、爆破、提权或横向移动。",
        "- WebShell相关场景仅以文件路径、上传目录、访问行为和风险标签等元数据表示。",
        "- 高风险与严重风险事件只触发人工复核或升级处置流程，不自动执行封禁、删除、隔离等真实动作。",
        "- 受限自动处置仅作为离线仿真动作记录审计日志，不连接真实网络、不下发真实封禁策略。",
        "",
        "## 三、数据规模与场景分布",
        "",
        f"- 告警总数：{len(alerts)}",
        f"- 聚合事件预警数：{len(incidents)}",
        "",
        "### 事件类型分布",
        "",
        "| 事件类型 | 告警数量 |",
        "| --- | ---: |",
    ]
    for event_type, count in sorted(scenario_counts.items()):
        lines.append(f"| {event_type} | {count} |")

    lines.extend(["", "### 风险等级分布", "", "| 风险等级 | 告警数量 |", "| --- | ---: |"])
    for risk_level, count in sorted(risk_counts.items()):
        lines.append(f"| {risk_level} | {count} |")

    lines.extend(["", "## 四、评价指标统计", "", "| 指标 | 数值 |", "| --- | ---: |"])
    for name, value in localize_metrics(metrics).items():
        rendered = _format_metric(name, value)
        lines.append(f"| {name} | {rendered} |")

    lines.extend(["", "## 五、典型告警研判案例", ""])
    for case in top_cases:
        alert = alert_map[case.alert_id]
        workflow = workflow_map[case.alert_id]
        lines.extend(
            [
                f"### {case.alert_id} - {get_risk_level_label(case.risk_level)}",
                "",
                f"- 资产：{alert.asset_id}（{get_asset_importance_label(alert.asset_importance)}）",
                f"- 事件类型：{get_event_type_label(alert.event_type)}",
                f"- 风险得分：{case.risk_score}",
                f"- 疑似攻击类型：{translate_value_by_field('suspected_attack_type', case.suspected_attack_type)}",
                f"- 证据摘要：{'；'.join(translate_text(item) for item in case.evidence_summary)}",
                f"- 工作流动作：{get_workflow_action_label(workflow.workflow_action)}，处理角色：{translate_value_by_field('assigned_role', workflow.assigned_role)}",
                "",
                "| 评分维度 | 得分 | 权重 | 贡献值 | 依据 |",
                "| --- | ---: | ---: | ---: | --- |",
            ]
        )
        for dim in [
            "asset_importance_score",
            "behavior_anomaly_score",
            "threat_feature_score",
            "correlation_score",
            "history_similarity_score",
        ]:
            item = case.explanation[dim]
            lines.append(
                f"| {get_score_dimension_label(dim)} | {item['score']} | {item['weight']} | "
                f"{item['contribution']} | {translate_text(item['evidence'])} |"
            )
        lines.append("")

    lines.extend(
        [
            "## 六、工作流触发结果",
            "",
            "| 工作流动作 | 告警数量 |",
            "| --- | ---: |",
        ]
    )
    for action, count in sorted(workflow_counts.items()):
        lines.append(f"| {action} | {count} |")
    lines.extend(
        [
            "",
            f"本次仿真中，受限自动处置仿真数量为 {simulated_block_count} 条。该动作表示高置信威胁情报命中且低业务影响的样本进入仿真临时封禁IP流程，仅用于验证工作流协同和审计闭环，不代表真实网络封禁。",
        ]
    )

    if incidents:
        lines.extend(["", "### 事件预警摘要", ""])
        for incident in incidents:
            lines.extend(
                [
                    f"#### {incident.incident_id}",
                    "",
                    f"- 事件类型：{translate_value_by_field('incident_type', incident.incident_type)}",
                    f"- 事件风险等级：{get_risk_level_label(incident.incident_risk_level)}",
                    f"- 关联告警编号：{', '.join(incident.related_alert_ids)}",
                    f"- 攻击链摘要：{translate_text(incident.attack_chain_summary)}",
                    f"- 推荐工作流动作：{get_workflow_action_label(incident.recommended_workflow_action)}",
                    "",
                ]
            )

    lines.extend(
        [
            "## 七、局限性说明",
            "",
            "1. 本项目为离线仿真验证，不代表真实核电厂管理网络的全部复杂性。",
            "2. 本项目不执行真实攻击行为。",
            "3. 本项目不连接真实网络系统。",
            "4. 本项目不生成真实恶意代码。",
            "5. 本项目结果依赖模拟数据和评分规则。",
            "6. 后续可接入脱敏历史告警数据进行进一步验证。",
            "7. 高风险事件必须由人工复核，智能体仅提供辅助研判和流程触发建议。",
            "8. 受限自动处置仅适用于高置信、低业务影响、可回滚的仿真样本，真实环境中仍需结合白名单、业务影响和人工审批策略。",
            "",
        ]
    )

    output_path.write_text("\n".join(lines), encoding="utf-8")


def _format_metric(name: str, value: Any) -> str:
    numeric = float(value)
    if name == "告警总数":
        return str(int(numeric))
    if name == "本地评分平均处理耗时":
        return f"{numeric:.4f} ms"
    return f"{numeric * 100:.2f}%"


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)
