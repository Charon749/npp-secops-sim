from __future__ import annotations

import json
from typing import Any

import pandas as pd


FIELD_NAME_MAP = {
    "alert_id": "告警编号",
    "timestamp": "时间戳",
    "source_device": "告警来源设备",
    "asset_id": "资产编号",
    "asset_type": "资产类型",
    "asset_importance": "资产重要性",
    "event_type": "事件类型",
    "event_description": "事件描述",
    "user_id": "用户编号",
    "src_ip": "源IP",
    "dst_ip": "目的IP",
    "file_path": "文件路径",
    "process_name": "进程名称",
    "behavior_tags": "行为标签",
    "related_alert_ids": "关联告警编号",
    "ground_truth_validity": "基准有效性",
    "ground_truth_risk_level": "基准风险等级",
    "ground_truth_event_type": "基准事件类型",
    "is_valid_alert": "是否有效告警",
    "risk_score": "风险评分",
    "risk_level": "风险等级",
    "suspected_attack_type": "疑似攻击类型",
    "evidence_summary": "证据摘要",
    "explanation": "研判解释",
    "recommended_actions": "处置建议",
    "need_human_review": "是否需要人工复核",
    "workflow_action": "工作流动作",
    "assigned_role": "分派角色",
    "status": "当前状态",
    "audit_log": "审计日志",
    "closed_loop_completed": "是否闭环完成",
    "judgement_time_ms": "本地评分处理耗时",
    "incident_id": "事件编号",
    "incident_type": "事件类型",
    "incident_risk_level": "事件风险等级",
    "attack_chain_summary": "攻击链摘要",
    "warning_report": "预警报告",
    "recommended_workflow_action": "推荐工作流动作",
    "related_alert_count": "关联告警数量",
    "webshell_risk_score": "可疑Web文件风险评分",
    "is_suspicious_webshell": "是否疑似WebShell",
    "total_alerts": "告警总数",
    "valid_alert_detection_rate": "有效告警识别率",
    "false_positive_rate": "误报率",
    "false_negative_rate": "漏报率",
    "risk_level_consistency_rate": "风险等级一致率",
    "average_judgement_time_ms": "本地评分平均处理耗时",
    "workflow_trigger_accuracy": "工作流触发准确率",
    "high_risk_human_review_rate": "高风险告警人工复核率",
    "closed_loop_rate": "流程闭环率",
    "asset_importance_score": "资产重要性评分",
    "behavior_anomaly_score": "行为异常性评分",
    "threat_feature_score": "威胁特征评分",
    "correlation_score": "多源关联评分",
    "history_similarity_score": "历史相似度评分",
    "score_name": "评分维度",
    "score": "得分",
    "weight": "权重",
    "contribution": "贡献值",
    "evidence": "依据",
    "count": "告警数量",
}

EVENT_TYPE_MAP = {
    "abnormal_login": "异常登录",
    "suspicious_web_file": "可疑Web文件",
    "port_scan": "端口探测",
    "abnormal_data_access": "异常数据访问",
    "outbound_connection": "异常外联",
    "normal_maintenance": "正常维护",
    "false_positive": "普通误报",
    "multi_stage_attack": "多阶段攻击链",
}

RISK_LEVEL_MAP = {
    "low": "低风险",
    "medium": "中风险",
    "high": "高风险",
    "critical": "严重风险",
}

ASSET_IMPORTANCE_MAP = {
    "low": "一般",
    "medium": "重要",
    "high": "高重要",
    "critical": "核心",
}

WORKFLOW_ACTION_MAP = {
    "archive": "自动归档",
    "create_ticket": "创建工单",
    "simulated_block_ip": "仿真临时封禁IP",
    "mandatory_human_review": "人工复核",
    "escalate_incident": "升级处置",
}

ASSET_TYPE_MAP = {
    "web_server": "Web服务器",
    "database_server": "数据库服务器",
    "database": "数据库服务器",
    "office_system": "办公系统",
    "office_server": "办公系统",
    "identity_system": "身份认证系统",
    "identity_server": "身份认证系统",
    "file_server": "文件服务器",
    "security_device": "安全设备",
    "security_tool": "安全设备",
    "backup_server": "备份服务器",
    "business_system": "业务系统",
}

SCORE_DIMENSION_MAP = {
    "asset_importance_score": "资产重要性评分",
    "behavior_anomaly_score": "行为异常性评分",
    "threat_feature_score": "威胁特征评分",
    "correlation_score": "多源关联评分",
    "history_similarity_score": "历史相似度评分",
    "score": "得分",
    "weight": "权重",
    "contribution": "贡献值",
    "evidence": "依据",
}

BEHAVIOR_TAG_MAP = {
    "non_working_hours": "非工作时间",
    "multiple_failed_logins": "多次登录失败",
    "failed_login_burst": "多次登录失败",
    "sensitive_account": "敏感账号",
    "unusual_login_location": "异常登录来源",
    "new_source_ip": "新来源IP",
    "suspicious_script": "可疑脚本",
    "unusual_upload_path": "异常上传路径",
    "obfuscated_pattern": "混淆特征",
    "abnormal_access_path": "异常访问路径",
    "external_callback_behavior": "疑似外联行为",
    "multi_port_access": "多端口访问",
    "high_frequency_connection": "高频连接",
    "high_connection_frequency": "高频连接",
    "external_probe": "外部探测",
    "sensitive_directory_access": "敏感目录访问",
    "large_volume_access": "大量访问",
    "data_exfiltration_indicator": "数据异常外传迹象",
    "multi_stage_indicator": "多阶段关联迹象",
    "threat_intel_ip_hit": "威胁情报IP命中",
    "high_confidence_ioc": "高置信威胁指标",
    "low_business_impact": "低业务影响",
    "auto_containment_candidate": "自动遏制候选",
    "scheduled_backup": "计划备份",
    "backup_window": "备份窗口",
    "planned_maintenance": "计划维护",
    "internal_scanner": "内部扫描工具",
    "authorized_internal_scan": "授权内部扫描",
    "known_admin_operation": "已知管理员操作",
}

ATTACK_TYPE_MAP = {
    "abnormal_login": "异常登录",
    "suspected_account_abuse": "疑似账号滥用",
    "suspected_webshell": "疑似WebShell",
    "suspected_webshell_metadata_event": "疑似WebShell元数据事件",
    "port_scan": "端口探测",
    "reconnaissance_or_probe": "侦察或探测",
    "data_access_anomaly": "数据访问异常",
    "abnormal_data_access": "异常数据访问",
    "suspicious_outbound_connection": "可疑外联",
    "multi_stage_attack": "多阶段攻击",
    "multi_stage_attack_chain": "多阶段攻击链",
    "false_positive": "普通误报",
    "benign_or_false_positive": "普通误报或良性事件",
    "normal_maintenance": "正常维护",
    "unknown": "未知类型",
}

STATUS_MAP = {
    "completed": "已完成",
    "pending": "待处理",
    "in_progress": "处理中",
    "archived": "已归档",
    "created": "已创建",
    "ticket_opened": "工单已创建",
    "simulated_blocked": "已记录仿真封禁",
    "escalated": "已升级",
    "review_required": "待人工复核",
    "pending_human_review": "待人工复核",
    "closed": "已关闭",
    "done": "已完成",
}

ROLE_MAP = {
    "security_operator": "安全运维人员",
    "soc_operator": "安全运维人员",
    "security_admin": "安全管理员",
    "security_analyst": "安全分析员",
    "incident_manager": "事件负责人",
    "incident_commander": "事件负责人",
    "auditor": "审计人员",
    "security_auditor": "审计人员",
    "automation_orchestrator": "自动化编排器",
    "tester": "测试人员",
    "system": "系统",
}

PROCESS_MAP = {
    "auth_service": "认证服务",
    "web_server": "Web服务",
    "network_monitor": "网络监测服务",
    "backup_agent": "备份代理",
    "patch_agent": "补丁代理",
    "scanner_agent": "扫描工具代理",
    "indexer": "索引服务",
    "monitor_agent": "监测代理",
    "sync_agent": "同步代理",
    "db_agent": "数据库代理",
    "release_agent": "发布代理",
    "batch_agent": "批处理代理",
    "replication_agent": "复制代理",
    "logrotate": "日志轮转服务",
    "etl_agent": "数据处理代理",
    "import_agent": "导入代理",
    "archive_agent": "归档代理",
    "db_client": "数据库客户端",
}

FIELD_VALUE_MAPS = {
    "event_type": EVENT_TYPE_MAP,
    "ground_truth_event_type": EVENT_TYPE_MAP,
    "incident_type": ATTACK_TYPE_MAP,
    "risk_level": RISK_LEVEL_MAP,
    "ground_truth_risk_level": RISK_LEVEL_MAP,
    "incident_risk_level": RISK_LEVEL_MAP,
    "asset_importance": ASSET_IMPORTANCE_MAP,
    "workflow_action": WORKFLOW_ACTION_MAP,
    "recommended_workflow_action": WORKFLOW_ACTION_MAP,
    "asset_type": ASSET_TYPE_MAP,
    "suspected_attack_type": ATTACK_TYPE_MAP,
    "status": STATUS_MAP,
    "assigned_role": ROLE_MAP,
    "process_name": PROCESS_MAP,
}

GENERIC_VALUE_MAP = {
    **EVENT_TYPE_MAP,
    **RISK_LEVEL_MAP,
    **WORKFLOW_ACTION_MAP,
    **ASSET_TYPE_MAP,
    **BEHAVIOR_TAG_MAP,
    **ATTACK_TYPE_MAP,
    **STATUS_MAP,
    **ROLE_MAP,
    **PROCESS_MAP,
    True: "是",
    False: "否",
    "True": "是",
    "False": "否",
    "true": "是",
    "false": "否",
}

TEXT_REPLACEMENTS = {
    "asset_importance is": "资产重要性为",
    "event_type is": "事件类型为",
    "behavior tags": "行为标签",
    "no behavior tags": "无行为标签",
    "benign maintenance tag reduces anomaly score": "维护类标签降低行为异常评分",
    "benign event type or authorized maintenance context": "良性事件类型或授权维护场景",
    "benign event type and only maintenance-related tags": "良性事件类型且仅包含维护类标签",
    "script-like extension detected": "检测到脚本类扩展名",
    "file path is located in an upload or temporary directory": "文件位于上传或临时目录",
    "behavior tag": "行为标签",
    "is present": "存在",
    "abnormal access path after upload is present": "上传后存在异常访问路径",
    "simulated external callback behavior is present": "存在模拟疑似外联行为",
    "related alerts provide correlation evidence": "关联告警提供上下文证据",
    "access count after upload is unusually high": "上传后访问次数异常偏高",
    "no WebShell-specific metadata evidence detected": "未检测到WebShell相关元数据证据",
    "threat-like tags": "威胁相关标签",
    "no explicit threat tags": "无显式威胁标签",
    "benign maintenance evidence reduces threat feature score": "维护类证据降低威胁特征评分",
    "related_alert_ids count is": "关联告警数量为",
    "same-asset event variety is": "同资产事件类型数量为",
    "similar simulated historical pattern for": "与模拟历史模式相似：",
    "weighted score falls into": "加权得分落入",
    "interval": "区间",
    "related alerts used for contextual scoring": "条关联告警用于上下文评分",
    "received judgement for alert": "接收告警研判结果：",
    "risk_level=": "风险等级=",
    "workflow_action=": "工作流动作=",
    "assigned_role=": "分派角色=",
    "status=": "当前状态=",
    "high-risk event is not auto-closed and requires manual review": "高风险事件不会自动关闭，需要人工复核",
    "low-risk alert archived with audit evidence retained": "低风险告警已归档，并保留审计证据",
    "matched limited auto-containment policy: high-confidence IOC, low business impact, non-critical asset": "命中受限自动处置策略：高置信威胁指标、低业务影响、非关键资产",
    "simulated temporary IP block recorded for offline experiment only; no real network policy was changed": "已记录仿真临时封禁IP，仅用于离线实验，未变更任何真实网络策略",
    "simulated action is reversible and retained for audit review": "仿真动作具备可回滚语义，并保留用于审计复核",
}


def translate_field_name(field_name: str) -> str:
    """将数据字段名转换为中文显示名。"""
    return FIELD_NAME_MAP.get(str(field_name), str(field_name))


def translate_value(value: Any) -> Any:
    """将英文枚举值、布尔值、状态值转换为中文显示值。"""
    if value is None:
        return "无"
    if isinstance(value, float) and pd.isna(value):
        return "无"
    if isinstance(value, bool):
        return "是" if value else "否"
    if isinstance(value, list):
        return translate_list_values(value)
    if isinstance(value, tuple):
        return translate_list_values(list(value))
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return "无"
        parsed = _try_parse_json(stripped)
        if isinstance(parsed, list):
            return translate_list_values(parsed)
        if isinstance(parsed, dict):
            return json.dumps(_translate_nested(parsed), ensure_ascii=False)
        if stripped in GENERIC_VALUE_MAP:
            return GENERIC_VALUE_MAP[stripped]
        return translate_text(stripped)
    return GENERIC_VALUE_MAP.get(value, value)


def translate_value_by_field(field_name: str, value: Any) -> Any:
    if value is None:
        return "无"
    if isinstance(value, float) and pd.isna(value):
        return "无"
    if isinstance(value, bool):
        return "是" if value else "否"
    if field_name in {"behavior_tags", "related_alert_ids", "evidence_summary", "recommended_actions", "audit_log"}:
        parsed = _normalize_list(value)
        return translate_list_values(parsed)
    if field_name == "explanation":
        return "查看详情"
    mapping = FIELD_VALUE_MAPS.get(field_name)
    if mapping:
        return mapping.get(str(value), translate_value(value))
    return translate_value(value)


def translate_list_values(values: Any) -> str:
    """将列表中的英文枚举值转换为中文显示值。"""
    if values is None:
        return "无"
    if isinstance(values, str):
        values = _normalize_list(values)
    if not values:
        return "无"
    translated = [str(translate_value(item)) for item in values]
    return "，".join(translated)


def localize_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """将 DataFrame 的列名和常见枚举值统一转换为中文，用于界面展示。"""
    localized = df.copy()
    for column in localized.columns:
        localized[column] = localized[column].map(lambda value, col=column: translate_value_by_field(col, value))
    localized = localized.rename(columns={column: translate_field_name(column) for column in localized.columns})
    return localized


def get_event_type_label(value: str) -> str:
    """事件类型中文化。"""
    return EVENT_TYPE_MAP.get(str(value), str(value))


def get_risk_level_label(value: str) -> str:
    """风险等级中文化。"""
    return RISK_LEVEL_MAP.get(str(value), str(value))


def get_workflow_action_label(value: str) -> str:
    """工作流动作中文化。"""
    return WORKFLOW_ACTION_MAP.get(str(value), str(value))


def get_asset_importance_label(value: str) -> str:
    return ASSET_IMPORTANCE_MAP.get(str(value), str(value))


def get_score_dimension_label(value: str) -> str:
    return SCORE_DIMENSION_MAP.get(str(value), str(value))


def translate_text(text: Any) -> str:
    if text is None:
        return "无"
    output = str(text)
    for source, target in TEXT_REPLACEMENTS.items():
        output = output.replace(source, target)
    for source, target in ASSET_IMPORTANCE_MAP.items():
        output = output.replace(f"资产重要性为 {source}", f"资产重要性为 {target}")
        output = output.replace(f"资产重要性为{source}", f"资产重要性为{target}")
    for mapping in [
        BEHAVIOR_TAG_MAP,
        EVENT_TYPE_MAP,
        RISK_LEVEL_MAP,
        WORKFLOW_ACTION_MAP,
        ASSET_TYPE_MAP,
        ATTACK_TYPE_MAP,
        STATUS_MAP,
        ROLE_MAP,
        PROCESS_MAP,
    ]:
        for source, target in mapping.items():
            output = output.replace(source, target)
    return output


def localize_metrics(metrics: dict[str, Any]) -> dict[str, Any]:
    return {translate_field_name(key): value for key, value in metrics.items()}


def localize_payload(payload: Any) -> Any:
    return _translate_nested(payload)


def localized_count_dataframe(df: pd.DataFrame, column: str, label: str) -> pd.DataFrame:
    if df.empty or column not in df.columns:
        return pd.DataFrame(columns=[label, "告警数量"])
    count_df = df[column].fillna("unknown").value_counts().rename_axis(column).reset_index(name="count")
    count_df[label] = count_df[column].map(lambda value: translate_value_by_field(column, value))
    count_df["告警数量"] = count_df["count"]
    return count_df[[label, "告警数量"]]


def localize_crosstab(table: pd.DataFrame) -> pd.DataFrame:
    localized = table.copy()
    localized.index = [get_risk_level_label(item) for item in localized.index]
    localized.columns = [get_risk_level_label(item) for item in localized.columns]
    localized.index.name = "基准风险等级"
    localized.columns.name = "研判风险等级"
    return localized


def _normalize_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return []
        parsed = _try_parse_json(stripped)
        if isinstance(parsed, list):
            return parsed
        return [item.strip() for item in stripped.split(";") if item.strip()] or [stripped]
    return [value]


def _translate_nested(value: Any) -> Any:
    if isinstance(value, dict):
        return {translate_field_name(key): _translate_nested(item) for key, item in value.items()}
    if isinstance(value, list):
        return [translate_value(item) for item in value]
    return translate_value(value)


def _try_parse_json(value: str) -> Any:
    if not (value.startswith("[") or value.startswith("{")):
        return value
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value
