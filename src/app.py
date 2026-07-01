from __future__ import annotations

import json
import sys
from dataclasses import asdict
from pathlib import Path
from time import perf_counter
from typing import Any

import pandas as pd
import streamlit as st


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.agents.alert_judgement_agent import AlertJudgementAgent
from src.agents.early_warning_agent import EarlyWarningAgent
from src.agents.webshell_detection_agent import WebShellDetectionAgent
from src.data_generator import generate_sample_data
from src.evaluation.metrics import compute_metrics, expected_workflow_action
from src.models import AlertRecord, IncidentWarning, JudgementResult, WorkflowResult
from src.reporting.report_generator import generate_outputs
from src.utils.display_mapping import (
    get_asset_importance_label,
    get_event_type_label,
    get_risk_level_label,
    get_score_dimension_label,
    get_workflow_action_label,
    localize_crosstab,
    localize_dataframe,
    localize_payload,
    localized_count_dataframe,
    translate_field_name,
    translate_list_values,
    translate_text,
    translate_value,
    translate_value_by_field,
)
from src.workflow.workflow_engine import WorkflowEngine


DATA_DIR = PROJECT_ROOT / "data"
OUTPUT_DIR = PROJECT_ROOT / "outputs"
ALERTS_PATH = DATA_DIR / "sample_alerts.jsonl"
RESULTS_PATH = OUTPUT_DIR / "simulation_results.csv"
REPORT_PATH = OUTPUT_DIR / "evaluation_report.md"

SCENARIO_OPTIONS = [
    "全部场景",
    "异常登录",
    "可疑Web文件",
    "端口探测",
    "异常数据访问",
    "异常外联",
    "正常维护",
    "普通误报",
    "多阶段攻击链",
]
RISK_FILTER_OPTIONS = {
    "全部": None,
    "低风险": "low",
    "中风险": "medium",
    "高风险": "high",
    "严重风险": "critical",
}
SCORE_DIMENSIONS = [
    "asset_importance_score",
    "behavior_anomaly_score",
    "threat_feature_score",
    "correlation_score",
    "history_similarity_score",
]


def main() -> None:
    st.set_page_config(
        page_title="核电厂管理网络告警研判智能体仿真平台 V0.2",
        layout="wide",
    )
    st.title("核电厂管理网络告警研判智能体仿真平台 V0.2")
    st.caption("离线仿真展示：模拟告警 -> 智能体研判 -> 工作流流转 -> 指标统计")
    st.warning(
        "本平台仅用于离线仿真验证，不连接真实网络系统，不执行真实攻击行为，"
        "不生成真实恶意代码。"
    )

    sidebar_state = render_sidebar()
    alerts = load_alerts()

    if sidebar_state["regenerate"]:
        with st.spinner("正在重新生成模拟告警数据..."):
            generate_sample_data(DATA_DIR)
        clear_runtime_state()
        alerts = load_alerts()
        st.sidebar.success(f"已生成 {len(alerts)} 条模拟告警。")

    if sidebar_state["run_simulation"]:
        if not alerts:
            with st.spinner("未检测到模拟样本数据，正在生成样本数据..."):
                generate_sample_data(DATA_DIR)
            alerts = load_alerts()
        with st.spinner("正在运行仿真研判、工作流流转和指标统计..."):
            st.session_state.dashboard_state = run_dashboard_simulation(alerts)
        st.sidebar.success("仿真研判已完成。")

    dashboard_state = get_dashboard_state(alerts)
    filtered_alerts = filter_alerts(
        alerts,
        sidebar_state["scenario"],
        RISK_FILTER_OPTIONS[sidebar_state["risk_level"]],
        dashboard_state["risk_by_alert_id"],
    )
    filtered_ids = {alert.alert_id for alert in filtered_alerts}
    filtered_results = filter_df_by_alert_ids(dashboard_state["results_df"], filtered_ids)

    tabs = st.tabs(
        [
            "平台概览",
            "原始告警",
            "智能体研判",
            "工作流流转",
            "事件预警",
            "指标统计与报告",
        ]
    )
    with tabs[0]:
        render_overview(filtered_alerts, filtered_results)
    with tabs[1]:
        render_raw_alerts(filtered_alerts)
    with tabs[2]:
        render_judgement_tab(filtered_results, dashboard_state)
    with tabs[3]:
        render_workflow_tab(filtered_results)
    with tabs[4]:
        render_incident_tab(dashboard_state["incidents"])
    with tabs[5]:
        render_metrics_report_tab(dashboard_state)


def render_sidebar() -> dict[str, Any]:
    st.sidebar.header("仿真控制")
    data_choice = st.sidebar.radio("数据选择", ["使用现有样本数据", "重新生成模拟数据"], index=0)
    regenerate = False
    if data_choice == "重新生成模拟数据":
        regenerate = st.sidebar.button("重新生成模拟数据")
    else:
        st.sidebar.caption("优先读取本地样本告警文件。")

    scenario = st.sidebar.selectbox("场景筛选", SCENARIO_OPTIONS, index=0)
    risk_level = st.sidebar.selectbox("风险等级筛选", list(RISK_FILTER_OPTIONS.keys()), index=0)
    run_simulation = st.sidebar.button("运行仿真研判", type="primary")
    st.sidebar.divider()
    st.sidebar.info(
        "展示数据来自模拟样本、脱敏结构化字段或本地输出文件；页面不会连接外部系统。"
    )
    return {
        "regenerate": regenerate,
        "scenario": scenario,
        "risk_level": risk_level,
        "run_simulation": run_simulation,
    }


def load_alerts() -> list[AlertRecord]:
    if not ALERTS_PATH.exists():
        return []
    alerts: list[AlertRecord] = []
    with ALERTS_PATH.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                alerts.append(AlertRecord.from_dict(json.loads(line)))
    return alerts


def run_dashboard_simulation(alerts: list[AlertRecord]) -> dict[str, Any]:
    judgement_agent = AlertJudgementAgent()
    webshell_agent = WebShellDetectionAgent()
    workflow_engine = WorkflowEngine()
    alert_by_id = {alert.alert_id: alert for alert in alerts}
    judgements: list[JudgementResult] = []
    workflows: list[WorkflowResult] = []
    webshell_results: dict[str, dict[str, Any]] = {}

    for alert in alerts:
        related_alerts = [
            alert_by_id[related_id]
            for related_id in alert.related_alert_ids
            if related_id in alert_by_id
        ]
        started = perf_counter()
        judgement = judgement_agent.judge_alert(alert, related_alerts=related_alerts)
        judgement.judgement_time_ms = round((perf_counter() - started) * 1000, 4)
        workflow = workflow_engine.process(judgement)
        judgements.append(judgement)
        workflows.append(workflow)

        if alert.event_type == "suspicious_web_file":
            webshell_results[alert.alert_id] = asdict(webshell_agent.analyze(alert))

    incidents = EarlyWarningAgent().aggregate(alerts)
    metrics = compute_metrics(alerts, judgements, workflows)
    generate_outputs(alerts, judgements, workflows, metrics, incidents, OUTPUT_DIR)
    results_df = load_results_df()
    return {
        "results_df": results_df,
        "metrics": metrics,
        "incidents": incidents,
        "webshell_results": webshell_results,
        "risk_by_alert_id": build_risk_map(alerts, results_df),
    }


def get_dashboard_state(alerts: list[AlertRecord]) -> dict[str, Any]:
    if "dashboard_state" in st.session_state:
        state = st.session_state.dashboard_state
        state["risk_by_alert_id"] = build_risk_map(alerts, state["results_df"])
        return state

    results_df = load_results_df()
    metrics = compute_metrics_from_results_df(results_df)
    incidents = EarlyWarningAgent().aggregate(alerts) if alerts else []
    return {
        "results_df": results_df,
        "metrics": metrics,
        "incidents": incidents,
        "webshell_results": {},
        "risk_by_alert_id": build_risk_map(alerts, results_df),
    }


def load_results_df() -> pd.DataFrame:
    if not RESULTS_PATH.exists():
        return pd.DataFrame()
    df = pd.read_csv(RESULTS_PATH)
    for column in [
        "ground_truth_validity",
        "is_valid_alert",
        "need_human_review",
        "closed_loop_completed",
    ]:
        if column in df.columns:
            df[column] = df[column].map(to_bool)
    return df


def compute_metrics_from_results_df(results_df: pd.DataFrame) -> dict[str, float]:
    if results_df.empty:
        return {}

    total = len(results_df)
    gt_valid = results_df["ground_truth_validity"].map(to_bool)
    pred_valid = results_df["is_valid_alert"].map(to_bool)
    true_positive = int((gt_valid & pred_valid).sum())
    true_negative = int((~gt_valid & ~pred_valid).sum())
    false_positive = int((~gt_valid & pred_valid).sum())
    false_negative = int((gt_valid & ~pred_valid).sum())
    expected_actions = results_df.apply(
        lambda row: expected_workflow_action(
            str(row.get("ground_truth_risk_level", "low")),
            alert=row.to_dict(),
            risk_score=float(row.get("risk_score") or 0.0),
        ),
        axis=1,
    )
    high_risk = results_df["risk_level"].isin(["high", "critical"])
    reviewed = results_df["need_human_review"].map(to_bool)

    return {
        "total_alerts": float(total),
        "valid_alert_detection_rate": safe_div(true_positive, true_positive + false_negative),
        "false_positive_rate": safe_div(false_positive, false_positive + true_negative),
        "false_negative_rate": safe_div(false_negative, true_positive + false_negative),
        "risk_level_consistency_rate": safe_div(
            int((results_df["risk_level"] == results_df["ground_truth_risk_level"]).sum()),
            total,
        ),
        "average_judgement_time_ms": float(results_df.get("judgement_time_ms", pd.Series([0])).mean()),
        "workflow_trigger_accuracy": safe_div(
            int((results_df["workflow_action"] == expected_actions).sum()),
            total,
        ),
        "high_risk_human_review_rate": safe_div(int((high_risk & reviewed).sum()), int(high_risk.sum())),
        "closed_loop_rate": safe_div(int(results_df["closed_loop_completed"].map(to_bool).sum()), total),
    }


def filter_alerts(
    alerts: list[AlertRecord],
    scenario: str,
    risk_level: str | None,
    risk_by_alert_id: dict[str, str],
) -> list[AlertRecord]:
    filtered = [alert for alert in alerts if scenario_matches(alert, scenario)]
    if risk_level:
        filtered = [
            alert
            for alert in filtered
            if risk_by_alert_id.get(alert.alert_id, alert.ground_truth_risk_level) == risk_level
        ]
    return filtered


def scenario_matches(alert: AlertRecord, scenario: str) -> bool:
    if scenario == "全部场景":
        return True
    event_map = {
        "异常登录": "abnormal_login",
        "可疑Web文件": "suspicious_web_file",
        "端口探测": "port_scan",
        "异常数据访问": "abnormal_data_access",
        "异常外联": "outbound_connection",
        "普通误报": "false_positive",
        "正常维护": "normal_maintenance",
    }
    if scenario == "多阶段攻击链":
        return (
            alert.ground_truth_event_type == "multi_stage_attack"
            or "multi_stage_indicator" in alert.behavior_tags
            or bool(alert.related_alert_ids)
        )
    return alert.event_type == event_map.get(scenario)


def render_overview(alerts: list[AlertRecord], results_df: pd.DataFrame) -> None:
    st.subheader("平台运行概览")
    if not alerts:
        st.info("未检测到模拟样本数据，请先生成样本数据。")
        return

    stats = build_overview_stats(alerts, results_df)
    metric_columns = st.columns(3)
    metric_columns[0].metric("告警总数", stats["total_alerts"])
    metric_columns[1].metric("有效告警数量", stats["valid_alerts"])
    metric_columns[2].metric("高风险告警数量", stats["high_risk_alerts"])
    metric_columns = st.columns(3)
    metric_columns[0].metric("需要人工复核数量", stats["human_review_count"])
    metric_columns[1].metric("已闭环流程数量", stats["closed_loop_count"])
    metric_columns[2].metric("本地评分平均处理耗时", f"{stats['avg_judgement_ms']:.4f} ms")
    metric_columns = st.columns(3)
    metric_columns[0].metric("受限自动处置仿真数量", stats["simulated_auto_count"])

    st.markdown(
        "本页面用于展示仿真平台整体运行状态。仿真平台通过构造结构化告警、日志和文件元数据记录，"
        "模拟安全检测或渗透测试演练在安全运维系统中留下的告警痕迹。告警研判智能体基于这些痕迹"
        "进行风险评分、证据聚合和处置建议生成，工作流引擎根据风险等级触发归档、工单、人工复核"
        "或升级处置流程；其中少量命中高置信威胁情报且低业务影响的样本，可触发受限自动处置仿真。"
        "该动作仅记录仿真临时封禁IP的审计结果，不连接真实网络、不下发真实策略。高风险和严重风险告警均进入人工复核"
        "或升级处置流程。当前比例为仿真样本分布结果，不代表真实核电厂管理网络告警比例。"
    )

    alert_df = alerts_to_df(alerts)
    chart_columns = st.columns(3)
    with chart_columns[0]:
        render_count_chart(alert_df, "event_type", "事件类型分布", "事件类型")
    with chart_columns[1]:
        if results_df.empty:
            render_count_chart(
                alert_df.rename(columns={"ground_truth_risk_level": "risk_level"}),
                "risk_level",
                "风险等级分布",
                "风险等级",
            )
        else:
            render_count_chart(results_df, "risk_level", "风险等级分布", "风险等级")
    with chart_columns[2]:
        if results_df.empty:
            st.info("运行仿真后显示工作流动作分布。")
        else:
            render_count_chart(results_df, "workflow_action", "工作流动作分布", "工作流动作")


def render_raw_alerts(alerts: list[AlertRecord]) -> None:
    st.subheader("原始告警数据")
    st.markdown(
        "本页展示仿真平台输入的结构化告警数据。数据用于模拟安全事件在日志系统、告警系统和"
        "工单系统中留下的痕迹，不包含真实攻击代码或真实敏感信息。"
    )
    if not alerts:
        st.info("暂无原始告警数据。")
        return

    alert_df = alerts_to_df(alerts)
    display_columns = [
        "alert_id",
        "timestamp",
        "source_device",
        "asset_id",
        "asset_type",
        "asset_importance",
        "event_type",
        "event_description",
        "behavior_tags",
        "related_alert_ids",
        "ground_truth_validity",
        "ground_truth_risk_level",
        "ground_truth_event_type",
    ]
    st.dataframe(localize_dataframe(alert_df[display_columns]), use_container_width=True, hide_index=True)

    st.markdown("#### 单条告警详情")
    selected_id = st.selectbox("选择告警编号", [alert.alert_id for alert in alerts], key="raw_alert_select")
    selected_alert = next(alert for alert in alerts if alert.alert_id == selected_id)
    if selected_alert.event_type == "suspicious_web_file":
        st.info("该可疑Web文件场景仅展示文件元数据与风险标签，不展示、不生成真实恶意代码。")
    detail_df = pd.DataFrame([asdict(selected_alert)])
    st.dataframe(localize_dataframe(detail_df), use_container_width=True, hide_index=True)
    with st.expander("查看完整告警数据"):
        st.caption("以下为原始调试数据。")
        st.json(asdict(selected_alert))


def render_judgement_tab(results_df: pd.DataFrame, dashboard_state: dict[str, Any]) -> None:
    st.subheader("告警研判智能体输出")
    st.markdown(
        "本页展示告警研判智能体对模拟告警的风险评分、风险等级、证据摘要和处置建议。"
        "智能体仅提供辅助研判结果；少量高置信低影响样本可触发受限自动处置仿真，"
        "高风险和严重风险告警仍需人工复核或升级处置。"
    )
    if results_df.empty:
        st.info("尚未运行仿真研判。请点击侧边栏“运行仿真研判”。")
        return

    st.markdown("#### 风险等级阈值说明")
    st.dataframe(
        pd.DataFrame(
            [
                {"风险等级": "低风险", "分数区间": "0-39 分", "流程约束": "自动归档并保留审计日志"},
                {"风险等级": "中风险", "分数区间": "40-59 分", "流程约束": "创建普通工单；满足高置信低影响条件时可触发受限自动处置仿真"},
                {"风险等级": "高风险", "分数区间": "60-79 分", "流程约束": "强制进入人工复核流程"},
                {"风险等级": "严重风险", "分数区间": "80-100 分", "流程约束": "触发升级处置流程"},
            ]
        ),
        use_container_width=True,
        hide_index=True,
    )

    columns = [
        "alert_id",
        "event_type",
        "risk_score",
        "risk_level",
        "suspected_attack_type",
        "is_valid_alert",
        "need_human_review",
        "workflow_action",
    ]
    st.dataframe(localize_dataframe(results_df[columns]), use_container_width=True, hide_index=True)

    st.markdown("#### 单条告警研判详情")
    selected_id = st.selectbox("选择告警编号", results_df["alert_id"].tolist(), key="judgement_alert_select")
    detail = row_by_alert_id(results_df, selected_id)
    explanation = parse_json_cell(detail.get("explanation"), {})
    evidence_summary = parse_json_cell(detail.get("evidence_summary"), [])
    recommended_actions = parse_json_cell(detail.get("recommended_actions"), [])
    behavior_tags = parse_json_cell(detail.get("behavior_tags"), [])

    cols = st.columns(4)
    cols[0].metric("风险评分", f"{float(detail['risk_score']):.2f}")
    cols[1].metric("风险等级", get_risk_level_label(str(detail["risk_level"])))
    cols[2].metric("疑似攻击类型", str(translate_value_by_field("suspected_attack_type", detail["suspected_attack_type"])))
    cols[3].metric("是否需要人工复核", translate_value(detail["need_human_review"]))

    render_risk_decision_basis(detail, explanation, behavior_tags, evidence_summary)

    st.markdown("#### 评分维度贡献")
    score_rows = []
    for dimension in SCORE_DIMENSIONS:
        item = explanation.get(dimension, {})
        score_rows.append(
            {
                "评分维度": get_score_dimension_label(dimension),
                "得分": item.get("score"),
                "权重": item.get("weight"),
                "贡献值": item.get("contribution"),
                "依据": translate_text(item.get("evidence", "")),
            }
        )
    st.dataframe(pd.DataFrame(score_rows), use_container_width=True, hide_index=True)

    st.markdown("#### 证据摘要")
    render_bullets(evidence_summary)
    st.markdown("#### 处置建议")
    render_bullets(recommended_actions)

    webshell_result = dashboard_state.get("webshell_results", {}).get(selected_id)
    if webshell_result:
        with st.expander("查看可疑Web文件元数据辅助分析"):
            st.json(localize_payload(webshell_result))

    with st.expander("查看完整研判解释"):
        st.caption("以下为中文结构化展示；字段来自本地仿真研判结果。")
        st.json(localize_payload(explanation))


def render_workflow_tab(results_df: pd.DataFrame) -> None:
    st.subheader("工作流流转结果")
    st.markdown(
        "本页展示告警研判结果进入工作流后的流转情况。系统根据风险等级触发自动归档、创建工单、"
        "受限自动处置仿真、人工复核或升级处置流程，并记录审计日志。智能体负责辅助研判，工作流负责过程约束；"
        "受限自动处置只记录仿真临时封禁IP，不连接真实网络、不下发真实策略，关键风险事件必须经过人工复核。"
    )
    if results_df.empty:
        st.info("尚未运行仿真研判。")
        return

    workflow_columns = [
        "alert_id",
        "risk_level",
        "workflow_action",
        "assigned_role",
        "status",
        "need_human_review",
        "closed_loop_completed",
    ]
    st.dataframe(localize_dataframe(results_df[workflow_columns]), use_container_width=True, hide_index=True)

    st.markdown(
        """
        **工作流规则说明**

        - 低风险：自动归档，保留审计日志
        - 中风险：创建普通工单，由安全运维人员处理
        - 受限自动处置：仅限中风险、非关键资产、高置信威胁情报命中且低业务影响的样本，记录仿真临时封禁IP
        - 高风险：强制进入人工复核流程
        - 严重风险：触发升级处置流程，并保留完整审计记录
        """
    )

    st.markdown("#### 单条告警流程详情")
    selected_id = st.selectbox("选择告警编号", results_df["alert_id"].tolist(), key="workflow_select")
    detail = row_by_alert_id(results_df, selected_id)
    audit_log = parse_json_cell(detail.get("audit_log"), [])
    workflow_label = get_workflow_action_label(str(detail["workflow_action"]))
    risk_label = get_risk_level_label(str(detail["risk_level"]))
    timeline = [
        "T+00:00 告警接入",
        "T+00:01 告警研判智能体完成评分",
        f"T+00:02 风险等级判定：{risk_label}",
        f"T+00:03 工作流动作触发：{workflow_label}",
        "T+00:04 审计日志写入",
        f"T+00:05 流程闭环状态更新：{translate_value(detail['closed_loop_completed'])}",
    ]
    if detail["risk_level"] in {"high", "critical"}:
        st.warning("该告警为高风险或严重风险，不允许显示为自动关闭。")
    if str(detail["workflow_action"]) == "simulated_block_ip":
        st.info("该告警触发的是受限自动处置仿真：系统仅记录临时封禁IP的模拟结果和审计日志，不执行真实网络封禁。")
    st.markdown("\n".join(f"- {item}" for item in timeline))
    with st.expander("查看审计日志"):
        render_bullets(audit_log)


def render_incident_tab(incidents: list[IncidentWarning]) -> None:
    st.subheader("事件预警与攻击链关联")
    st.markdown(
        "本页展示事件预警智能体对多条相关告警的聚合结果。系统根据资产、时间窗口、关联告警和"
        "行为标签，识别可能的多阶段安全事件，并生成预警报告。该模块不展示真实攻击细节或可执行代码。"
    )
    if not incidents:
        st.info("暂无满足阈值的多源事件预警。")
        return

    incident_df = pd.DataFrame([asdict(item) for item in incidents])
    display_columns = [
        "incident_id",
        "incident_type",
        "incident_risk_level",
        "related_alert_ids",
        "recommended_workflow_action",
    ]
    st.dataframe(localize_dataframe(incident_df[display_columns]), use_container_width=True, hide_index=True)
    st.markdown("#### 攻击链摘要")
    st.markdown("外部探测 -> 异常登录尝试 -> 可疑文件上传 -> 异常访问路径 -> 异常外联 -> 敏感目录访问")

    st.markdown("#### 预警报告")
    selected_id = st.selectbox("选择事件编号", incident_df["incident_id"].tolist(), key="incident_select")
    detail = incident_df[incident_df["incident_id"] == selected_id].iloc[0].to_dict()
    st.markdown(f"**攻击链摘要**：{translate_text(detail['attack_chain_summary'])}")
    st.markdown("**证据摘要**")
    render_bullets(detail["evidence_summary"])
    st.markdown(
        f"**推荐工作流动作**：{get_workflow_action_label(str(detail['recommended_workflow_action']))}"
    )
    with st.expander("查看预警报告"):
        st.write(translate_text(detail["warning_report"]))


def render_metrics_report_tab(dashboard_state: dict[str, Any]) -> None:
    st.subheader("指标统计与评估报告")
    st.markdown(
        "本页展示仿真验证的统计指标和评估报告。相关指标用于分析告警研判智能体在有效告警识别、"
        "风险等级判断、工作流触发和流程闭环方面的表现。"
    )
    results_df = dashboard_state["results_df"]
    metrics = dashboard_state["metrics"]
    if results_df.empty or not metrics:
        st.info("尚未运行仿真研判，或未检测到历史结果文件。")
        if st.button("生成报告所需仿真结果"):
            alerts = load_alerts()
            if not alerts:
                generate_sample_data(DATA_DIR)
                alerts = load_alerts()
            st.session_state.dashboard_state = run_dashboard_simulation(alerts)
            st.rerun()
        return

    metric_items = [
        "total_alerts",
        "valid_alert_detection_rate",
        "false_positive_rate",
        "false_negative_rate",
        "risk_level_consistency_rate",
        "average_judgement_time_ms",
        "workflow_trigger_accuracy",
        "high_risk_human_review_rate",
        "closed_loop_rate",
    ]
    for row_start in range(0, len(metric_items), 3):
        cols = st.columns(3)
        for col, name in zip(cols, metric_items[row_start : row_start + 3]):
            col.metric(translate_field_name(name), format_metric_value(name, metrics.get(name, 0.0)))

    chart_cols = st.columns(3)
    with chart_cols[0]:
        render_count_chart(results_df, "risk_level", "风险等级分布", "风险等级")
    with chart_cols[1]:
        render_count_chart(results_df, "workflow_action", "工作流动作分布", "工作流动作")
    with chart_cols[2]:
        render_count_chart(results_df, "event_type", "事件类型分布", "事件类型")

    st.markdown("#### 基准风险等级与研判风险等级对比")
    comparison = pd.crosstab(results_df["ground_truth_risk_level"], results_df["risk_level"])
    st.dataframe(localize_crosstab(comparison), use_container_width=True)

    st.markdown("#### 评估报告预览")
    if REPORT_PATH.exists():
        st.markdown(REPORT_PATH.read_text(encoding="utf-8"))
    else:
        st.warning("未检测到评估报告，请先运行仿真研判。")

    download_cols = st.columns(2)
    if RESULTS_PATH.exists():
        download_cols[0].download_button(
            "下载仿真结果CSV",
            data=RESULTS_PATH.read_bytes(),
            file_name="simulation_results.csv",
            mime="text/csv",
        )
    if REPORT_PATH.exists():
        download_cols[1].download_button(
            "下载评估报告Markdown",
            data=REPORT_PATH.read_bytes(),
            file_name="evaluation_report.md",
            mime="text/markdown",
        )


def build_overview_stats(alerts: list[AlertRecord], results_df: pd.DataFrame) -> dict[str, Any]:
    if results_df.empty:
        valid_count = sum(alert.ground_truth_validity for alert in alerts)
        high_count = sum(alert.ground_truth_risk_level in {"high", "critical"} for alert in alerts)
        return {
            "total_alerts": len(alerts),
            "valid_alerts": valid_count,
            "high_risk_alerts": high_count,
            "human_review_count": 0,
            "simulated_auto_count": 0,
            "closed_loop_count": 0,
            "avg_judgement_ms": 0.0,
        }
    return {
        "total_alerts": len(results_df),
        "valid_alerts": int(results_df["is_valid_alert"].map(to_bool).sum()),
        "high_risk_alerts": int(results_df["risk_level"].isin(["high", "critical"]).sum()),
        "human_review_count": int(results_df["need_human_review"].map(to_bool).sum()),
        "simulated_auto_count": int((results_df["workflow_action"] == "simulated_block_ip").sum()),
        "closed_loop_count": int(results_df["closed_loop_completed"].map(to_bool).sum()),
        "avg_judgement_ms": float(results_df.get("judgement_time_ms", pd.Series([0])).mean()),
    }


def render_risk_decision_basis(
    detail: dict[str, Any],
    explanation: dict[str, Any],
    behavior_tags: list[Any],
    evidence_summary: list[Any],
) -> None:
    risk_level = str(detail["risk_level"])
    risk_score = float(detail["risk_score"])
    workflow_action = str(detail["workflow_action"])
    tag_text = translate_list_values(behavior_tags)
    if tag_text == "无" and evidence_summary:
        tag_text = "；".join(translate_text(item) for item in evidence_summary[:2])

    basis_rows = [
        {"判定要素": "风险总分", "说明": f"{risk_score:.2f} 分"},
        {"判定要素": "当前风险等级阈值", "说明": risk_threshold_text(risk_level)},
        {
            "判定要素": "资产重要性评分贡献",
            "说明": dimension_contribution_text(explanation, "asset_importance_score"),
        },
        {
            "判定要素": "行为异常性评分贡献",
            "说明": dimension_contribution_text(explanation, "behavior_anomaly_score"),
        },
        {
            "判定要素": "威胁特征评分贡献",
            "说明": dimension_contribution_text(explanation, "threat_feature_score"),
        },
        {
            "判定要素": "多源关联评分贡献",
            "说明": dimension_contribution_text(explanation, "correlation_score"),
        },
        {"判定要素": "主要证据标签", "说明": tag_text},
        {"判定要素": "触发的工作流动作", "说明": get_workflow_action_label(workflow_action)},
    ]

    st.markdown("#### 风险等级判定依据")
    st.dataframe(pd.DataFrame(basis_rows), use_container_width=True, hide_index=True)
    st.info(risk_decision_sentence(risk_level, risk_score, workflow_action, tag_text))
    if workflow_action == "simulated_block_ip":
        st.success(
            "触发受限自动处置原因：该告警命中威胁情报IP、高置信威胁指标、低业务影响和自动遏制候选标签，"
            "且不涉及关键资产、多阶段攻击链或严重风险。平台仅记录仿真临时封禁IP，不执行真实网络动作。"
        )
    if risk_level == "high":
        st.warning(
            "触发人工复核原因：风险评分进入高风险区间，同时资产重要性、行为异常、威胁特征或多源关联"
            "中至少一项贡献较高，需要安全人员结合日志和业务背景确认。"
        )
    elif risk_level == "critical":
        st.error(
            "触发升级处置原因：风险评分进入严重风险区间，且存在较强威胁特征或多源关联证据，"
            "必须进入升级处置流程并保留完整审计记录。"
        )


def dimension_contribution_text(explanation: dict[str, Any], dimension: str) -> str:
    item = explanation.get(dimension, {})
    score = item.get("score", "无")
    weight = item.get("weight", "无")
    contribution = item.get("contribution", "无")
    evidence = translate_text(item.get("evidence", "无"))
    return f"原始得分 {score}，权重 {weight}，贡献值 {contribution}；依据：{evidence}"


def risk_threshold_text(risk_level: str) -> str:
    thresholds = {
        "low": "0-39 分，对应低风险",
        "medium": "40-59 分，对应中风险",
        "high": "60-79 分，对应高风险",
        "critical": "80-100 分，对应严重风险",
    }
    return thresholds.get(risk_level, "未知阈值")


def risk_decision_sentence(risk_level: str, risk_score: float, workflow_action: str, tag_text: str) -> str:
    risk_label = get_risk_level_label(risk_level)
    workflow_label = get_workflow_action_label(workflow_action)
    if risk_level == "low":
        reason = "风险总分低于 40 分，未形成明显威胁聚合证据，因此按低风险处理。"
    elif risk_level == "medium":
        if workflow_action == "simulated_block_ip":
            reason = (
                "风险总分位于 40-59 分区间，同时命中高置信威胁情报、低业务影响和非关键资产约束，"
                "因此进入受限自动处置仿真流程。"
            )
        else:
            reason = "风险总分位于 40-59 分区间，存在一定异常迹象，但尚未达到强制人工复核阈值。"
    elif risk_level == "high":
        reason = "风险总分位于 60-79 分区间，已达到高风险阈值，需要进入人工复核流程。"
    else:
        reason = "风险总分达到 80 分及以上，属于严重风险，需要触发升级处置流程。"
    return (
        f"该告警风险总分为 {risk_score:.2f} 分，被判定为{risk_label}。{reason}"
        f"主要证据标签为：{tag_text}。触发的工作流动作为：{workflow_label}。"
    )


def alerts_to_df(alerts: list[AlertRecord]) -> pd.DataFrame:
    return pd.DataFrame([asdict(alert) for alert in alerts])


def render_count_chart(df: pd.DataFrame, column: str, title: str, label: str) -> None:
    st.markdown(f"#### {title}")
    if df.empty or column not in df.columns:
        st.info("暂无可展示数据。")
        return
    count_df = localized_count_dataframe(df, column, label)
    st.bar_chart(count_df, x=label, y="告警数量")


def render_bullets(items: Any) -> None:
    if isinstance(items, str):
        items = [items]
    if not items:
        st.write("- 暂无")
        return
    st.markdown("\n".join(f"- {translate_text(item)}" for item in items))


def build_risk_map(alerts: list[AlertRecord], results_df: pd.DataFrame) -> dict[str, str]:
    if results_df.empty or "alert_id" not in results_df.columns:
        return {alert.alert_id: alert.ground_truth_risk_level for alert in alerts}
    return dict(zip(results_df["alert_id"], results_df["risk_level"]))


def filter_df_by_alert_ids(df: pd.DataFrame, alert_ids: set[str]) -> pd.DataFrame:
    if df.empty or not alert_ids:
        return pd.DataFrame(columns=df.columns)
    return df[df["alert_id"].isin(alert_ids)].copy()


def row_by_alert_id(df: pd.DataFrame, alert_id: str) -> dict[str, Any]:
    return df[df["alert_id"] == alert_id].iloc[0].to_dict()


def parse_json_cell(value: Any, default: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return default
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return default
    return default


def format_metric_value(name: str, value: Any) -> str:
    numeric = float(value or 0.0)
    if name == "total_alerts":
        return str(int(numeric))
    if name == "average_judgement_time_ms":
        return f"{numeric:.4f} ms"
    return f"{numeric * 100:.2f}%"


def to_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1", "yes", "y"}
    return False


def safe_div(numerator: float, denominator: float) -> float:
    return 0.0 if denominator == 0 else round(float(numerator) / float(denominator), 4)


def clear_runtime_state() -> None:
    if "dashboard_state" in st.session_state:
        del st.session_state.dashboard_state


if __name__ == "__main__":
    main()
