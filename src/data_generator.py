from __future__ import annotations

import csv
import json
from datetime import datetime, timedelta
from pathlib import Path

from src.models import AlertRecord, to_plain_dict


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"
BASE_TIME = datetime(2026, 5, 18, 8, 0, 0)


ASSETS = [
    {
        "asset_id": "ASSET-WEB-01",
        "asset_name": "management portal web server",
        "asset_type": "web_server",
        "asset_importance": "high",
        "ip_address": "10.10.20.11",
    },
    {
        "asset_id": "ASSET-WEB-02",
        "asset_name": "document exchange web server",
        "asset_type": "web_server",
        "asset_importance": "critical",
        "ip_address": "10.10.20.12",
    },
    {
        "asset_id": "ASSET-AD-01",
        "asset_name": "identity directory server",
        "asset_type": "identity_server",
        "asset_importance": "critical",
        "ip_address": "10.10.10.5",
    },
    {
        "asset_id": "ASSET-DB-01",
        "asset_name": "operation management database",
        "asset_type": "database",
        "asset_importance": "critical",
        "ip_address": "10.10.30.21",
    },
    {
        "asset_id": "ASSET-FILE-01",
        "asset_name": "engineering file server",
        "asset_type": "file_server",
        "asset_importance": "high",
        "ip_address": "10.10.40.18",
    },
    {
        "asset_id": "ASSET-OA-01",
        "asset_name": "office automation server",
        "asset_type": "office_server",
        "asset_importance": "medium",
        "ip_address": "10.10.50.30",
    },
    {
        "asset_id": "ASSET-BACKUP-01",
        "asset_name": "backup server",
        "asset_type": "backup_server",
        "asset_importance": "medium",
        "ip_address": "10.10.60.8",
    },
    {
        "asset_id": "ASSET-SCAN-01",
        "asset_name": "authorized internal scanner",
        "asset_type": "security_tool",
        "asset_importance": "low",
        "ip_address": "10.10.70.9",
    },
]


def asset(asset_id: str) -> dict[str, str]:
    return next(item for item in ASSETS if item["asset_id"] == asset_id)


def make_alert(
    index: int,
    minutes: int,
    asset_id: str,
    event_type: str,
    description: str,
    user_id: str,
    src_ip: str,
    file_path: str,
    process_name: str,
    behavior_tags: list[str],
    related_alert_ids: list[str],
    gt_valid: bool,
    gt_risk: str,
    gt_event_type: str | None = None,
) -> AlertRecord:
    asset_info = asset(asset_id)
    return AlertRecord(
        alert_id=f"A{index:04d}",
        timestamp=(BASE_TIME + timedelta(minutes=minutes)).isoformat(),
        source_device=f"{asset_info['asset_type']}-log",
        asset_id=asset_id,
        asset_type=asset_info["asset_type"],
        asset_importance=asset_info["asset_importance"],
        event_type=event_type,
        event_description=description,
        user_id=user_id,
        src_ip=src_ip,
        dst_ip=asset_info["ip_address"],
        file_path=file_path,
        process_name=process_name,
        behavior_tags=behavior_tags,
        related_alert_ids=related_alert_ids,
        ground_truth_validity=gt_valid,
        ground_truth_risk_level=gt_risk,
        ground_truth_event_type=gt_event_type or event_type,
    )


def build_sample_alerts() -> list[AlertRecord]:
    alerts: list[AlertRecord] = []
    idx = 1

    abnormal_login_cases = [
        ("ASSET-OA-01", "admin_ops", "172.16.1.23", ["failed_login_burst", "sensitive_account"], "medium"),
        ("ASSET-WEB-01", "webadmin", "172.16.8.44", ["non_working_hours", "new_source_ip"], "medium"),
        ("ASSET-FILE-01", "db_backup", "172.16.9.18", ["non_working_hours", "new_source_ip"], "medium"),
        ("ASSET-OA-01", "contractor01", "172.16.4.50", ["failed_login_burst"], "medium"),
        ("ASSET-FILE-01", "engineer_a", "172.16.6.71", ["new_source_ip"], "medium"),
        ("ASSET-OA-01", "svc_sync", "172.16.8.45", ["failed_login_burst", "non_working_hours"], "medium"),
        ("ASSET-FILE-01", "portal_admin", "203.0.113.10", ["sensitive_account"], "medium"),
        ("ASSET-OA-01", "user_023", "172.16.4.60", ["failed_login_burst"], "medium"),
        ("ASSET-FILE-01", "project_mgr", "172.16.6.81", ["non_working_hours"], "medium"),
        ("ASSET-DB-01", "readonly_ops", "172.16.9.20", ["new_source_ip", "sensitive_account"], "high"),
        ("ASSET-WEB-01", "web_editor", "172.16.8.49", ["failed_login_burst"], "medium"),
        ("ASSET-AD-01", "admin_ops", "198.51.100.42", ["failed_login_burst", "non_working_hours", "sensitive_account"], "critical"),
    ]
    for case in abnormal_login_cases:
        asset_id, user_id, src_ip, tags, risk = case
        alerts.append(
            make_alert(
                idx,
                5 * idx,
                asset_id,
                "abnormal_login",
                "simulated abnormal authentication log pattern",
                user_id,
                src_ip,
                "",
                "auth_service",
                tags,
                [],
                True,
                risk,
            )
        )
        idx += 1

    webshell_cases = [
        ("ASSET-OA-01", "/srv/oa/upload/report.jsp", ["unusual_upload_path"], "medium"),
        ("ASSET-WEB-02", "/opt/portal/uploads/temp/cache.aspx", ["suspicious_script", "obfuscated_pattern"], "critical"),
        ("ASSET-OA-01", "/srv/oa/upload/img/avatar.php", ["abnormal_access_path"], "medium"),
        ("ASSET-OA-01", "/srv/oa/tmp/help.jspx", ["unusual_upload_path"], "medium"),
        ("ASSET-OA-01", "/srv/oa/upload/form.asp", ["suspicious_script"], "medium"),
        ("ASSET-OA-01", "/srv/oa/uploads/2026/note.aspx", ["obfuscated_pattern"], "medium"),
        ("ASSET-WEB-02", "/opt/portal/uploads/doc/print.ashx", ["suspicious_script", "external_callback_behavior"], "critical"),
        ("ASSET-WEB-01", "/var/www/html/tmp/sys.jsp", ["suspicious_script", "obfuscated_pattern", "abnormal_access_path"], "critical"),
        ("ASSET-OA-01", "/srv/oa/uploads/chart.js", ["unusual_upload_path"], "medium"),
        ("ASSET-WEB-02", "/opt/portal/upload/audit.jsp", ["suspicious_script", "abnormal_access_path"], "high"),
        ("ASSET-OA-01", "/srv/oa/upload/style.aspx", ["obfuscated_pattern"], "medium"),
        ("ASSET-WEB-02", "/opt/portal/tmp/api.php", ["suspicious_script", "obfuscated_pattern", "external_callback_behavior"], "critical"),
    ]
    for path_case in webshell_cases:
        asset_id, file_path, tags, risk = path_case
        alerts.append(
            make_alert(
                idx,
                7 * idx,
                asset_id,
                "suspicious_web_file",
                "simulated suspicious web file metadata event without malicious content",
                "web_uploader",
                "198.51.100.25",
                file_path,
                "web_server",
                tags,
                [],
                True,
                risk,
            )
        )
        idx += 1

    scan_cases = [
        ("ASSET-SCAN-01", "172.16.70.9", ["authorized_internal_scan", "multi_port_access"], "low"),
        ("ASSET-SCAN-01", "172.16.70.10", ["authorized_internal_scan", "multi_port_access"], "low"),
        ("ASSET-SCAN-01", "172.16.70.11", ["authorized_internal_scan", "high_connection_frequency"], "low"),
        ("ASSET-OA-01", "172.16.70.9", ["authorized_internal_scan", "multi_port_access"], "low"),
        ("ASSET-FILE-01", "203.0.113.24", ["high_connection_frequency"], "medium"),
        ("ASSET-FILE-01", "203.0.113.25", ["external_probe"], "medium"),
        ("ASSET-WEB-01", "198.51.100.30", ["multi_port_access"], "medium"),
        ("ASSET-BACKUP-01", "172.16.70.9", ["authorized_internal_scan", "multi_port_access"], "low"),
        ("ASSET-WEB-02", "198.51.100.31", ["multi_port_access", "high_connection_frequency"], "high"),
        ("ASSET-OA-01", "198.51.100.32", ["external_probe"], "medium"),
    ]
    for asset_id, src_ip, tags, risk in scan_cases:
        is_valid = "authorized_internal_scan" not in tags
        alerts.append(
            make_alert(
                idx,
                9 * idx,
                asset_id,
                "port_scan",
                "simulated multi-port connection frequency anomaly",
                "unknown",
                src_ip,
                "",
                "network_monitor",
                tags,
                [],
                is_valid,
                risk if is_valid else "low",
            )
        )
        idx += 1

    chain_specs = [
        ("ASSET-WEB-02", "port_scan", "external reconnaissance against management portal", "unknown", "203.0.113.88", "", "network_monitor", ["multi_port_access", "external_probe"], "high"),
        ("ASSET-WEB-02", "abnormal_login", "login attempts after reconnaissance", "portal_admin", "203.0.113.88", "", "auth_service", ["failed_login_burst", "sensitive_account"], "high"),
        ("ASSET-WEB-02", "suspicious_web_file", "metadata-only suspicious upload after abnormal login", "portal_admin", "203.0.113.88", "/opt/portal/uploads/temp/module.jsp", "web_server", ["suspicious_script", "unusual_upload_path"], "critical"),
        ("ASSET-WEB-02", "suspicious_web_file", "abnormal access path observed after upload", "portal_admin", "203.0.113.88", "/opt/portal/uploads/temp/module.jsp", "web_server", ["abnormal_access_path", "obfuscated_pattern"], "critical"),
        ("ASSET-WEB-02", "outbound_connection", "simulated outbound connection behavior after suspicious web access", "portal_admin", "203.0.113.88", "", "web_server", ["external_callback_behavior"], "critical"),
        ("ASSET-WEB-02", "abnormal_data_access", "sensitive directory access after chained anomalies", "portal_admin", "203.0.113.88", "/opt/portal/config/", "web_server", ["sensitive_directory_access", "multi_stage_indicator"], "critical"),
        ("ASSET-DB-01", "abnormal_data_access", "correlated database access from chained portal incident", "readonly_ops", "10.10.20.12", "/data/ops/sensitive/", "db_client", ["sensitive_directory_access", "multi_stage_indicator"], "critical"),
    ]
    chain_ids: list[str] = []
    for spec in chain_specs:
        asset_id, event_type, desc, user_id, src_ip, file_path, process, tags, risk = spec
        related = chain_ids[-3:].copy()
        if "multi_stage_indicator" in tags:
            related = chain_ids.copy()
        alert = make_alert(
            idx,
            20 * 60 + len(chain_ids) * 4,
            asset_id,
            event_type,
            desc,
            user_id,
            src_ip,
            file_path,
            process,
            tags,
            related,
            True,
            risk,
            "multi_stage_attack",
        )
        alerts.append(alert)
        chain_ids.append(alert.alert_id)
        idx += 1

    benign_cases = [
        ("ASSET-BACKUP-01", "normal_maintenance", "scheduled backup read during maintenance window", "backup_svc", "172.16.60.20", "/backup/nightly/", "backup_agent", ["backup_window"], "low"),
        ("ASSET-OA-01", "normal_maintenance", "planned OA patch validation", "maint_user", "172.16.4.10", "", "patch_agent", ["planned_maintenance"], "low"),
        ("ASSET-SCAN-01", "false_positive", "authorized scanner heartbeat", "scanner", "10.10.70.9", "", "scanner_agent", ["authorized_internal_scan"], "low"),
        ("ASSET-FILE-01", "normal_maintenance", "scheduled index rebuild", "file_svc", "172.16.40.9", "/index/", "indexer", ["planned_maintenance"], "low"),
        ("ASSET-WEB-01", "false_positive", "business upload of static report file", "report_user", "172.16.8.20", "/var/www/html/upload/report.pdf", "web_server", ["planned_maintenance"], "low"),
        ("ASSET-BACKUP-01", "normal_maintenance", "backup validation access", "backup_svc", "172.16.60.21", "/backup/check/", "backup_agent", ["backup_window"], "low"),
        ("ASSET-OA-01", "false_positive", "known monitoring account login", "monitor", "172.16.4.11", "", "monitor_agent", ["planned_maintenance"], "low"),
        ("ASSET-SCAN-01", "normal_maintenance", "internal compliance scan", "scanner", "10.10.70.9", "", "scanner_agent", ["authorized_internal_scan"], "low"),
        ("ASSET-FILE-01", "false_positive", "department file synchronization", "sync_svc", "172.16.40.12", "/share/sync/", "sync_agent", ["backup_window"], "low"),
        ("ASSET-DB-01", "normal_maintenance", "planned database statistics collection", "db_maint", "172.16.30.12", "", "db_agent", ["planned_maintenance"], "low"),
        ("ASSET-WEB-02", "false_positive", "release pipeline health check", "release_bot", "172.16.20.50", "/opt/portal/health", "release_agent", ["planned_maintenance"], "low"),
        ("ASSET-BACKUP-01", "false_positive", "retention policy check", "backup_svc", "172.16.60.21", "/backup/retention/", "backup_agent", ["backup_window"], "low"),
        ("ASSET-OA-01", "normal_maintenance", "office workflow batch job", "batch_svc", "172.16.4.15", "", "batch_agent", ["planned_maintenance"], "low"),
        ("ASSET-SCAN-01", "false_positive", "expected vulnerability signature update", "scanner", "10.10.70.9", "", "scanner_agent", ["authorized_internal_scan"], "low"),
        ("ASSET-FILE-01", "normal_maintenance", "archive compression task", "archive_svc", "172.16.40.13", "/archive/", "archive_agent", ["backup_window"], "low"),
        ("ASSET-AD-01", "false_positive", "directory replication health check", "replica_svc", "172.16.10.8", "", "replication_agent", ["planned_maintenance"], "low"),
        ("ASSET-WEB-01", "normal_maintenance", "approved web log rotation", "log_svc", "172.16.20.8", "/var/log/web/", "logrotate", ["planned_maintenance"], "low"),
        ("ASSET-DB-01", "false_positive", "approved ETL validation read", "etl_svc", "172.16.30.18", "/data/stage/", "etl_agent", ["backup_window"], "low"),
        ("ASSET-OA-01", "normal_maintenance", "approved helpdesk import job", "helpdesk_svc", "172.16.4.19", "/srv/oa/import/", "import_agent", ["planned_maintenance"], "low"),
        ("ASSET-WEB-02", "false_positive", "business portal static asset refresh", "release_bot", "172.16.20.51", "/opt/portal/static/", "release_agent", ["planned_maintenance"], "low"),
    ]
    for item in benign_cases:
        asset_id, event_type, desc, user_id, src_ip, file_path, process, tags, risk = item
        alerts.append(
            make_alert(
                idx,
                30 * 60 + idx,
                asset_id,
                event_type,
                desc,
                user_id,
                src_ip,
                file_path,
                process,
                tags,
                [],
                False,
                risk,
            )
        )
        idx += 1

    return alerts


def write_jsonl(alerts: list[AlertRecord], output_path: Path) -> None:
    with output_path.open("w", encoding="utf-8") as handle:
        for alert in alerts:
            handle.write(json.dumps(to_plain_dict(alert), ensure_ascii=False) + "\n")


def write_csv(rows: list[dict[str, object]], output_path: Path) -> None:
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def generate_sample_data(data_dir: Path | None = None) -> list[AlertRecord]:
    target_dir = data_dir or DATA_DIR
    target_dir.mkdir(parents=True, exist_ok=True)
    alerts = build_sample_alerts()

    write_jsonl(alerts, target_dir / "sample_alerts.jsonl")
    write_csv(ASSETS, target_dir / "assets.csv")
    ground_truth_rows = [
        {
            "alert_id": alert.alert_id,
            "ground_truth_validity": alert.ground_truth_validity,
            "ground_truth_risk_level": alert.ground_truth_risk_level,
            "ground_truth_event_type": alert.ground_truth_event_type,
            "expected_workflow_action": expected_workflow_action(alert.ground_truth_risk_level),
        }
        for alert in alerts
    ]
    write_csv(ground_truth_rows, target_dir / "ground_truth.csv")
    return alerts


def expected_workflow_action(risk_level: str) -> str:
    return {
        "low": "archive",
        "medium": "create_ticket",
        "high": "mandatory_human_review",
        "critical": "escalate_incident",
    }[risk_level]


def main() -> None:
    alerts = generate_sample_data()
    print(f"Generated {len(alerts)} simulated alerts in {DATA_DIR}")


if __name__ == "__main__":
    main()
