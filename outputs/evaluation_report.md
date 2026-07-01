# 核电厂管理网络告警研判智能体与工作流协同仿真平台 V0.1 评价报告

## 项目简介

本项目用于离线验证“模拟安全告警输入 -> 可解释风险评分 -> 工作流触发 -> 指标统计 -> 报告输出”的最小闭环，服务于硕士论文第四章的仿真平台构建与验证分析。

## 仿真边界说明

- 本项目只使用模拟数据或脱敏化结构字段，不连接真实核电厂管理网络。
- 本项目不生成真实攻击代码、不生成真实 WebShell、不执行扫描、利用、爆破、提权或横向移动。
- WebShell 场景仅以文件路径、上传目录、访问行为和风险标签等元数据表示。
- high 与 critical 风险事件只触发人工复核或升级处置流程，不自动执行封禁、删除、隔离等真实动作。

## 数据规模

- 告警总数：61
- 聚合事件预警数：1

## 场景分布

| 场景类型 | 数量 |
| --- | ---: |
| abnormal_data_access | 2 |
| abnormal_login | 13 |
| false_positive | 10 |
| normal_maintenance | 10 |
| outbound_connection | 1 |
| port_scan | 11 |
| suspicious_web_file | 14 |

## 评价指标表

| 指标 | 数值 |
| --- | ---: |
| total_alerts | 61 |
| valid_alert_detection_rate | 1.0000 |
| false_positive_rate | 0.0000 |
| false_negative_rate | 0.0000 |
| risk_level_consistency_rate | 0.8852 |
| average_judgement_time_ms | 0.1262 |
| workflow_trigger_accuracy | 0.8852 |
| high_risk_human_review_rate | 1.0000 |
| closed_loop_rate | 0.3607 |

## 典型告警研判案例

### A0040 - critical

- 资产：ASSET-WEB-02（critical）
- 事件类型：abnormal_data_access
- 风险得分：92.09
- 疑似类型：abnormal_data_access
- 证据摘要：涉及 critical 重要性资产 ASSET-WEB-02；检测到行为标签：multi_stage_indicator, sensitive_directory_access；存在 related_alert_ids 或同资产告警关联；威胁特征评分较高，需要人工结合日志复核
- 工作流动作：escalate_incident，处理角色：incident_commander

  - asset_importance_score: score=95.0, weight=0.25, contribution=23.75, evidence=asset_importance is critical
  - behavior_anomaly_score: score=95.75, weight=0.25, contribution=23.94, evidence=event_type is abnormal_data_access; behavior tags: multi_stage_indicator, sensitive_directory_access
  - threat_feature_score: score=95.0, weight=0.2, contribution=19.0, evidence=threat-like tags: multi_stage_indicator, sensitive_directory_access
  - correlation_score: score=90.0, weight=0.2, contribution=18.0, evidence=related_alert_ids count is 5; same-asset event variety is 5
  - history_similarity_score: score=74.0, weight=0.1, contribution=7.4, evidence=similar simulated historical pattern for abnormal_data_access

### A0041 - critical

- 资产：ASSET-DB-01（critical）
- 事件类型：abnormal_data_access
- 风险得分：92.09
- 疑似类型：abnormal_data_access
- 证据摘要：涉及 critical 重要性资产 ASSET-DB-01；检测到行为标签：multi_stage_indicator, sensitive_directory_access；存在 related_alert_ids 或同资产告警关联；威胁特征评分较高，需要人工结合日志复核
- 工作流动作：escalate_incident，处理角色：incident_commander

  - asset_importance_score: score=95.0, weight=0.25, contribution=23.75, evidence=asset_importance is critical
  - behavior_anomaly_score: score=95.75, weight=0.25, contribution=23.94, evidence=event_type is abnormal_data_access; behavior tags: multi_stage_indicator, sensitive_directory_access
  - threat_feature_score: score=95.0, weight=0.2, contribution=19.0, evidence=threat-like tags: multi_stage_indicator, sensitive_directory_access
  - correlation_score: score=90.0, weight=0.2, contribution=18.0, evidence=related_alert_ids count is 6; same-asset event variety is 1
  - history_similarity_score: score=74.0, weight=0.1, contribution=7.4, evidence=similar simulated historical pattern for abnormal_data_access

### A0037 - critical

- 资产：ASSET-WEB-02（critical）
- 事件类型：suspicious_web_file
- 风险得分：84.36
- 疑似类型：suspected_webshell_metadata_event
- 证据摘要：涉及 critical 重要性资产 ASSET-WEB-02；可疑 Web 文件场景仅基于文件元数据和行为标签进行仿真判断；检测到行为标签：suspicious_script, unusual_upload_path；存在 related_alert_ids 或同资产告警关联；威胁特征评分较高，需要人工结合日志复核
- 工作流动作：escalate_incident，处理角色：incident_commander

  - asset_importance_score: score=95.0, weight=0.25, contribution=23.75, evidence=asset_importance is critical
  - behavior_anomaly_score: score=91.25, weight=0.25, contribution=22.81, evidence=event_type is suspicious_web_file; behavior tags: suspicious_script, unusual_upload_path
  - threat_feature_score: score=90.0, weight=0.2, contribution=18.0, evidence=script-like extension detected: .jsp; file path is located in an upload or temporary directory; behavior tag suspicious_script is present; related alerts provide correlation evidence
  - correlation_score: score=65.0, weight=0.2, contribution=13.0, evidence=related_alert_ids count is 2; same-asset event variety is 3
  - history_similarity_score: score=68.0, weight=0.1, contribution=6.8, evidence=similar simulated historical pattern for suspicious_web_file

## 工作流触发结果

| 工作流动作 | 数量 |
| --- | ---: |
| archive | 22 |
| create_ticket | 11 |
| escalate_incident | 4 |
| mandatory_human_review | 24 |

## 事件预警结果

### INC0001

- 事件类型：multi_stage_attack_chain
- 风险等级：critical
- 关联告警：A0035, A0036, A0037, A0038, A0039, A0040, A0041
- 攻击链摘要：该事件疑似由外部探测、异常登录尝试、可疑文件上传、敏感目录或数据访问、对外连接行为构成，具备多阶段攻击链特征，建议触发人工复核和升级处置流程。
- 推荐流程：escalate_incident


## 局限性说明

1. 本项目为离线仿真验证，不代表真实核电厂管理网络的全部复杂性。
2. 本项目不执行真实攻击行为。
3. 本项目结果依赖模拟数据和评分规则。
4. 后续可接入脱敏历史告警数据进行进一步验证。
5. 高风险事件必须由人工复核，智能体仅提供辅助研判和流程触发建议。
