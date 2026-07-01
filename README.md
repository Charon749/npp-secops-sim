# npp-secops-sim

`npp-secops-sim` 是“核电厂管理网络告警研判智能体与工作流协同仿真平台”的 V0.1 最小可运行版本。项目面向硕士论文《面向核电厂管理网络的告警研判智能体与工作流协同安全运维方法研究》的第四章仿真验证，重点验证离线告警研判、风险评分、工作流触发和实验指标统计闭环。

## 项目功能

- 生成不少于 50 条模拟告警数据，覆盖异常登录、WebShell 可疑文件元数据、端口探测、多源攻击链和普通误报场景。
- 使用 `AlertJudgementAgent` 对单条告警或相关告警进行可解释规则评分。
- 使用 `WebShellDetectionAgent` 对可疑 Web 文件元数据进行安全仿真评分，不生成、不执行恶意代码。
- 使用 `EarlyWarningAgent` 将相关告警聚合为多阶段事件预警。
- 使用 `WorkflowEngine` 根据风险等级触发归档、工单、人工复核或升级处置流程。
- 输出 `outputs/simulation_results.csv` 和 `outputs/evaluation_report.md`。
- 使用 pytest 覆盖核心规则、工作流、指标和报告输出。

## 项目结构

```text
npp-secops-sim/
├── README.md
├── requirements.txt
├── data/
│   ├── sample_alerts.jsonl
│   ├── assets.csv
│   └── ground_truth.csv
├── outputs/
│   ├── simulation_results.csv
│   └── evaluation_report.md
├── src/
│   ├── main.py
│   ├── data_generator.py
│   ├── models.py
│   ├── agents/
│   │   ├── alert_judgement_agent.py
│   │   ├── webshell_detection_agent.py
│   │   └── early_warning_agent.py
│   ├── workflow/
│   │   └── workflow_engine.py
│   ├── evaluation/
│   │   └── metrics.py
│   └── reporting/
│       └── report_generator.py
└── tests/
    ├── test_alert_judgement_agent.py
    ├── test_workflow_engine.py
    └── test_metrics.py
```

## 安全边界

本项目只进行离线仿真验证，不连接真实核电厂管理网络，不访问外部互联网，不执行任何真实攻击行为。项目不会生成真实攻击代码或真实 WebShell，不执行端口扫描、漏洞利用、爆破、提权、横向移动等操作。WebShell 场景只使用文件路径、上传目录、访问行为、关联告警和风险标签等元数据进行模拟。`high` 与 `critical` 风险事件只能触发人工复核或升级处置流程，不能自动执行封禁、删除、隔离等真实动作。

## 运行方法

安装依赖：

```bash
pip install -r requirements.txt
```

生成样本数据：

```bash
python -m src.data_generator
```

运行仿真：

```bash
python -m src.main
```

运行测试：

```bash
pytest
```

## 样本数据说明

`data/sample_alerts.jsonl` 中每条告警包含 `alert_id`、`timestamp`、`source_device`、`asset_id`、`asset_type`、`asset_importance`、`event_type`、`event_description`、`user_id`、`src_ip`、`dst_ip`、`file_path`、`process_name`、`behavior_tags`、`related_alert_ids`、`ground_truth_validity`、`ground_truth_risk_level` 和 `ground_truth_event_type`。

`data/assets.csv` 保存模拟资产清单，`data/ground_truth.csv` 保存实验评价所需的标签和预期工作流动作。

## 评价指标说明

平台计算以下指标：

- `total_alerts`：告警总数。
- `valid_alert_detection_rate`：有效告警识别率。
- `false_positive_rate`：误报率。
- `false_negative_rate`：漏报率。
- `risk_level_consistency_rate`：风险等级一致率。
- `average_judgement_time_ms`：平均研判耗时。
- `workflow_trigger_accuracy`：工作流触发正确率。
- `high_risk_human_review_rate`：高风险告警人工复核率。
- `closed_loop_rate`：流程闭环率。

## 用于硕士论文第四章的方式

论文第四章可以围绕“仿真平台构建与验证分析”展开：先说明离线安全边界和数据脱敏原则，再描述数据生成、告警研判智能体、WebShell 元数据识别智能体、事件预警智能体和工作流引擎的模块划分，随后使用 `simulation_results.csv` 和 `evaluation_report.md` 展示场景覆盖、典型案例解释、工作流触发结果和评价指标。

需要注意的是，V0.1 的结果依赖模拟数据和规则权重，适合验证方法流程、可解释性和闭环机制，不应表述为真实核电厂管理网络中的最终检测能力。

## 后续扩展方向

- 接入脱敏历史告警数据，替换或补充模拟样本。
- 增加规则权重敏感性分析和消融实验。
- 将工作流状态从 CSV 扩展为 SQLite 或轻量审计库。
- 增加 Streamlit 可视化界面，用于展示告警列表、解释字段、事件链和指标趋势。
- 引入人工复核反馈字段，形成规则优化和案例库迭代机制。

## 可视化界面说明

本项目提供 Streamlit 可视化界面，用于展示核电厂管理网络告警研判智能体仿真平台的运行过程。界面支持全中文展示，包括原始告警、智能体研判结果、评分解释、工作流流转状态、事件预警和指标统计结果。

代码内部仍保留英文数据字段，界面层通过 `src/utils/display_mapping.py` 中的统一映射字典转换为中文显示。该设计既便于代码维护，也便于论文第四章截图和答辩演示。

该界面仅用于离线仿真展示，不代表真实核电厂管理网络运行界面，不连接真实网络系统，不执行真实攻击行为，不生成真实恶意代码，也不会展示自动封禁、自动删除、自动隔离等真实处置动作。

运行命令：

```bash
streamlit run src/app.py
```

如果没有样本数据，可以先运行：

```bash
python -m src.data_generator
```

也可以在界面侧边栏选择“重新生成模拟数据”。点击“运行仿真研判”后，界面会调用现有的 `AlertJudgementAgent`、`WebShellDetectionAgent`、`EarlyWarningAgent`、`WorkflowEngine`、`metrics.py` 和 `report_generator.py`，并刷新 `outputs/simulation_results.csv` 与 `outputs/evaluation_report.md`。

界面包含 6 个中文标签页：

1. **平台概览**：展示告警总数、有效告警、高风险告警、人工复核、闭环流程、平均研判时间，以及事件类型、风险等级和工作流动作分布。
2. **原始告警**：展示筛选后的模拟告警表格，可选择单条告警查看中文结构化详情；可疑Web文件场景只展示文件元数据和风险标签。
3. **智能体研判**：展示风险得分、风险等级、疑似攻击类型、评分维度贡献、证据摘要、处置建议和完整研判解释。
4. **工作流流转**：展示工作流动作、处理角色、状态、审计日志和单条告警流程时间线，强调高风险与严重风险必须人工复核或升级处置。
5. **事件预警**：展示事件预警智能体聚合出的多阶段攻击链事件、关联告警、攻击链摘要和预警报告。
6. **指标统计与报告**：展示评价指标卡片、风险等级分布、工作流动作分布、事件类型分布、基准风险等级对比表、评估报告预览，并提供仿真结果 CSV 和评估报告 Markdown 下载按钮。

常见问题：

- **没有数据文件怎么办？** 在侧边栏选择“重新生成模拟数据”，或运行 `python -m src.data_generator`。
- **没有报告怎么办？** 点击侧边栏“运行仿真研判”，或在“指标统计与报告”页点击生成报告所需仿真结果。
- **界面是否会访问真实网络？** 不会。界面只读取本地 `data/` 和 `outputs/` 文件，并调用本地仿真模块。
- **可疑Web文件页面是否包含恶意代码？** 不包含。页面只展示文件路径、行为标签、关联告警和风险评分等元数据。

该可视化模块可用于论文第四章“仿真平台构建与验证分析”的展示。平台通过原始告警、智能体研判结果、评分解释、工作流流转状态和评价指标统计，直观呈现告警研判智能体与工作流协同机制的运行过程。界面截图可作为论文中“仿真平台运行界面”或答辩 PPT 展示材料。
