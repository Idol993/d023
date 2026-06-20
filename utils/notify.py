import json
import logging
from typing import Dict, Any, Optional


class Notifier:
    def __init__(self, config: dict):
        self.enabled = config.get("enabled", False)
        self.channels = config.get("channels", [])
        self.logger = logging.getLogger("notifier")

    def notify(
        self,
        title: str,
        message: str,
        level: str = "info",
        recipients: Optional[list] = None,
        extra: Optional[Dict[str, Any]] = None,
    ):
        if not self.enabled:
            self.logger.info(f"通知已禁用，跳过: [{level}] {title}")
            return

        payload = {
            "title": title,
            "message": message,
            "level": level,
            "recipients": recipients or [],
            "extra": extra or {},
        }

        for channel in self.channels:
            channel_type = channel.get("type")
            try:
                if channel_type == "webhook":
                    self._send_webhook(channel, payload)
                elif channel_type == "email":
                    self._send_email(channel, payload)
                elif channel_type == "sms":
                    self._send_sms(channel, payload)
                else:
                    self.logger.warning(f"未知通知渠道类型: {channel_type}")
            except Exception as e:
                self.logger.error(f"通知发送失败 [{channel_type}]: {e}")

    def _send_webhook(self, channel: dict, payload: dict):
        self.logger.info(
            f"Webhook通知 -> {channel.get('url')}: {json.dumps(payload, ensure_ascii=False)[:200]}"
        )

    def _send_email(self, channel: dict, payload: dict):
        self.logger.info(
            f"邮件通知 -> {channel.get('smtp_host')}:{channel.get('smtp_port')}: {payload['title']}"
        )

    def _send_sms(self, channel: dict, payload: dict):
        self.logger.info(
            f"短信通知 -> {channel.get('provider')}: {payload['title']}"
        )

    def notify_release_created(self, release_id: str, version: str, release_type: str):
        self.notify(
            title="发布申请已创建",
            message=f"发布单 {release_id}，版本 {version}，类型 {release_type}",
            level="info",
            extra={"release_id": release_id, "version": version, "release_type": release_type},
        )

    def notify_pre_check_result(self, release_id: str, passed: bool, details: str):
        level = "info" if passed else "error"
        self.notify(
            title=f"前置校验{'通过' if passed else '未通过'}",
            message=f"发布单 {release_id}: {details}",
            level=level,
            extra={"release_id": release_id, "passed": passed},
        )

    def notify_approval_required(self, release_id: str, role: str, level: int):
        self.notify(
            title="审批待处理",
            message=f"发布单 {release_id} 需要第{level}级审批（{role}）",
            level="warning",
            extra={"release_id": release_id, "role": role, "level": level},
        )

    def notify_approval_result(self, release_id: str, approved: bool, role: str):
        level = "info" if approved else "error"
        self.notify(
            title=f"审批{'通过' if approved else '被拒绝'}",
            message=f"发布单 {release_id} {role}审批{'通过' if approved else '被拒绝'}",
            level=level,
            extra={"release_id": release_id, "approved": approved, "role": role},
        )

    def notify_canary_progress(self, release_id: str, stage: str, status: str):
        self.notify(
            title="灰度发布进展",
            message=f"发布单 {release_id} 阶段[{stage}] 状态: {status}",
            level="info",
            extra={"release_id": release_id, "stage": stage, "status": status},
        )

    def notify_circuit_breaker_triggered(self, release_id: str, reason: str):
        self.notify(
            title="熔断器触发告警",
            message=f"发布单 {release_id} 熔断触发: {reason}",
            level="critical",
            extra={"release_id": release_id, "reason": reason},
        )

    def notify_rollback(self, release_id: str, from_version: str, to_version: str):
        self.notify(
            title="版本已回滚",
            message=f"发布单 {release_id} 从 {from_version} 回滚至 {to_version}",
            level="critical",
            extra={
                "release_id": release_id,
                "from_version": from_version,
                "to_version": to_version,
            },
        )

    def notify_release_completed(self, release_id: str, version: str):
        self.notify(
            title="版本发布完成",
            message=f"发布单 {release_id}，版本 {version} 已全量发布",
            level="info",
            extra={"release_id": release_id, "version": version},
        )
