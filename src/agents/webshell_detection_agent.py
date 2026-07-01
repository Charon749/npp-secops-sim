from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any

from src.models import AlertRecord, WebShellAnalysis, parse_list


class WebShellDetectionAgent:
    """Metadata-only WebShell risk detector for offline simulation.

    The agent never creates, loads, or executes script content. It only scores
    simulated file metadata and behavior tags.
    """

    SCRIPT_EXTENSIONS = {".php", ".jsp", ".jspx", ".asp", ".aspx", ".ashx", ".js"}
    UPLOAD_PATH_HINTS = ("/upload", "/uploads", "/tmp", "/temp", "/wwwroot/upload")

    def analyze(self, alert_or_payload: AlertRecord | dict[str, Any]) -> WebShellAnalysis:
        payload = self._normalize(alert_or_payload)
        file_path = str(payload.get("file_path") or "")
        behavior_tags = set(parse_list(payload.get("behavior_tags")))
        related_alert_ids = parse_list(payload.get("related_alert_ids"))
        access_count = int(payload.get("access_count_after_upload") or 0)

        score = 0
        evidence: list[str] = []
        suffix = PurePosixPath(file_path.replace("\\", "/")).suffix.lower()

        if suffix in self.SCRIPT_EXTENSIONS:
            score += 20
            evidence.append(f"script-like extension detected: {suffix}")
        if any(hint in file_path.lower().replace("\\", "/") for hint in self.UPLOAD_PATH_HINTS):
            score += 15
            evidence.append("file path is located in an upload or temporary directory")
        if "suspicious_script" in behavior_tags:
            score += 25
            evidence.append("behavior tag suspicious_script is present")
        if "obfuscated_pattern" in behavior_tags:
            score += 20
            evidence.append("behavior tag obfuscated_pattern is present")
        if "abnormal_access_path" in behavior_tags:
            score += 15
            evidence.append("abnormal access path after upload is present")
        if "external_callback_behavior" in behavior_tags:
            score += 15
            evidence.append("simulated external callback behavior is present")
        if related_alert_ids:
            score += min(15, 5 * len(related_alert_ids))
            evidence.append("related alerts provide correlation evidence")
        if access_count >= 10:
            score += 10
            evidence.append("access count after upload is unusually high")

        score = min(100, score)
        is_suspicious = score >= 60
        actions = [
            "人工复核可疑文件元数据",
            "检查上传账号、时间和访问路径",
            "核查 Web 访问日志与外联日志",
            "确认后再执行隔离或清理等真实操作",
        ]
        if not is_suspicious:
            actions = ["保留审计记录", "结合维护窗口和业务变更记录复核"]

        return WebShellAnalysis(
            webshell_risk_score=round(float(score), 2),
            is_suspicious_webshell=is_suspicious,
            evidence=evidence or ["no WebShell-specific metadata evidence detected"],
            recommended_actions=actions,
        )

    def _normalize(self, alert_or_payload: AlertRecord | dict[str, Any]) -> dict[str, Any]:
        if isinstance(alert_or_payload, AlertRecord):
            return {
                "file_path": alert_or_payload.file_path,
                "behavior_tags": alert_or_payload.behavior_tags,
                "related_alert_ids": alert_or_payload.related_alert_ids,
            }
        return dict(alert_or_payload)
