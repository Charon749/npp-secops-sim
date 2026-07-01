from src.agents.alert_judgement_agent import AlertJudgementAgent
from src.agents.early_warning_agent import EarlyWarningAgent
from src.agents.webshell_detection_agent import WebShellDetectionAgent
from src.models import AlertRecord


def make_alert(
    alert_id="A9001",
    event_type="suspicious_web_file",
    asset_importance="high",
    tags=None,
    related=None,
):
    return AlertRecord(
        alert_id=alert_id,
        timestamp="2026-05-18T08:00:00",
        source_device="web_server-log",
        asset_id="ASSET-WEB-01",
        asset_type="web_server",
        asset_importance=asset_importance,
        event_type=event_type,
        event_description="test alert",
        user_id="tester",
        src_ip="198.51.100.1",
        dst_ip="10.10.20.11",
        file_path="/var/www/html/upload/test.jsp",
        process_name="web_server",
        behavior_tags=tags or ["suspicious_script", "obfuscated_pattern", "abnormal_access_path"],
        related_alert_ids=related or [],
        ground_truth_validity=True,
        ground_truth_risk_level="high",
        ground_truth_event_type=event_type,
    )


def test_risk_total_score_formula_is_weighted_sum():
    agent = AlertJudgementAgent()
    score = agent.calculate_total_score(
        {
            "asset_importance_score": 90,
            "behavior_anomaly_score": 85,
            "threat_feature_score": 90,
            "correlation_score": 80,
            "history_similarity_score": 50,
        }
    )
    assert score == 82.75


def test_risk_level_mapping_boundaries():
    assert AlertJudgementAgent.map_risk_level(39.99) == "low"
    assert AlertJudgementAgent.map_risk_level(40) == "medium"
    assert AlertJudgementAgent.map_risk_level(59.99) == "medium"
    assert AlertJudgementAgent.map_risk_level(60) == "high"
    assert AlertJudgementAgent.map_risk_level(79.99) == "high"
    assert AlertJudgementAgent.map_risk_level(80) == "critical"


def test_explanation_contains_score_weight_contribution_and_evidence():
    agent = AlertJudgementAgent()
    result = agent.judge_alert(make_alert(related=["A0001", "A0002"]))
    for dimension in agent.DEFAULT_WEIGHTS:
        item = result.explanation[dimension]
        assert {"score", "weight", "contribution", "evidence"} <= set(item)
    assert "final_assessment" in result.explanation


def test_webshell_metadata_scoring_identifies_suspicious_file():
    agent = WebShellDetectionAgent()
    result = agent.analyze(
        {
            "file_path": "/opt/portal/uploads/temp/a.jsp",
            "behavior_tags": [
                "suspicious_script",
                "obfuscated_pattern",
                "abnormal_access_path",
                "external_callback_behavior",
            ],
            "related_alert_ids": ["A0001", "A0002"],
            "access_count_after_upload": 20,
        }
    )
    assert result.is_suspicious_webshell is True
    assert result.webshell_risk_score >= 60
    assert result.evidence


def test_early_warning_agent_aggregates_multi_source_chain():
    alerts = [
        make_alert("A9101", "port_scan", "high", ["multi_port_access", "external_probe"]),
        make_alert("A9102", "abnormal_login", "high", ["failed_login_burst"], ["A9101"]),
        make_alert("A9103", "suspicious_web_file", "high", ["suspicious_script"], ["A9101", "A9102"]),
        make_alert("A9104", "outbound_connection", "high", ["external_callback_behavior"], ["A9101", "A9102", "A9103"]),
    ]
    warnings = EarlyWarningAgent().aggregate(alerts)
    assert warnings
    assert warnings[0].incident_type == "multi_stage_attack_chain"
    assert "A9101" in warnings[0].related_alert_ids
