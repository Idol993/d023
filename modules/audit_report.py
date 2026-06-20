import json
import os
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional

from models.schemas import (
    ReleaseType,
    ReleaseStatus,
    ReviewReport,
    PreCheckReport,
    ApprovalFlow,
    CanaryStage,
)


class AuditEngine:
    def __init__(self, config: dict, db=None):
        self.enabled = config.get("enabled", True)
        self.log_retention_days = config.get("log_retention_days", 365)
        self.require_electronic_sig = config.get("require_electronic_signature", True)
        self.report_output_dir = config.get("report_output_dir", "./reports")
        self.report_format = config.get("report_format", "html")
        self.metrics_retention_days = config.get("metrics_retention_days", 90)
        self.db = db
        self.logger = logging.getLogger("audit.engine")

    def log_action(
        self,
        release_id: str,
        action: str,
        actor: str,
        details: Dict[str, Any],
        electronic_signature: str = "",
    ):
        if not self.enabled:
            return

        if self.require_electronic_sig and not electronic_signature:
            self.logger.warning(
                f"审计日志缺少电子签名 [release_id={release_id}, action={action}]"
            )

        self.logger.info(
            f"审计记录 [release_id={release_id}]: action={action}, actor={actor}"
        )

        if self.db:
            self.db.add_audit_log(
                release_id=release_id,
                action=action,
                actor=actor,
                details=details,
                electronic_signature=electronic_signature,
            )

    def get_audit_trail(self, release_id: str) -> List[Dict[str, Any]]:
        if self.db:
            return self.db.get_audit_logs(release_id=release_id)
        return []

    def verify_audit_integrity(self, release_id: str, current_status: str = None) -> Dict[str, Any]:
        self.logger.info(f"验证审计完整性 [release_id={release_id}, status={current_status}]")

        logs = self.get_audit_trail(release_id)

        integrity_issues = []

        if not logs:
            integrity_issues.append("无审计日志记录")

        required_actions = ["release_created", "pre_check_completed"]

        if current_status:
            needs_approval = [
                "approval_passed", "canary_deploying",
                "canary_completed", "fully_released",
                "release_completed", "approval_rejected",
            ]
            if current_status in needs_approval:
                required_actions.append("approval_completed")

            needs_canary = [
                "canary_deploying", "canary_completed",
                "fully_released", "release_completed", "rolled_back",
            ]
            if current_status in needs_canary:
                required_actions.append("canary_started")

            needs_release = ["fully_released", "release_completed"]
            if current_status in needs_release:
                required_actions.append("release_completed")

            needs_report = ["fully_released", "release_completed"]
            if current_status in needs_report:
                required_actions.append("review_report_generated")

        existing_actions = {log.get("action") for log in logs}
        for action in required_actions:
            if action not in existing_actions:
                integrity_issues.append(f"缺少必要审计事件: {action}")

        if self.require_electronic_sig:
            unsigned_logs = [log for log in logs if not log.get("electronic_signature")]
            if unsigned_logs:
                integrity_issues.append(
                    f"存在{len(unsigned_logs)}条缺少电子签名的审计记录"
                )

        return {
            "release_id": release_id,
            "integrity_valid": len(integrity_issues) == 0,
            "total_log_entries": len(logs),
            "issues": integrity_issues,
            "verified_at": datetime.now().isoformat(),
        }

    def generate_review_report(
        self,
        release_id: str,
        version: str,
        release_type: ReleaseType,
        pre_check_report: Optional[PreCheckReport] = None,
        approval_flow: Optional[ApprovalFlow] = None,
        canary_stages: Optional[List[CanaryStage]] = None,
        rollback_performed: bool = False,
        rollback_details: Optional[Dict[str, Any]] = None,
    ) -> ReviewReport:
        self.logger.info(f"生成复盘报表 [release_id={release_id}]")

        report = ReviewReport(
            release_id=release_id,
            version=version,
            release_type=release_type,
        )

        if pre_check_report:
            report.pre_check_summary = self._summarize_pre_check(pre_check_report)

        if approval_flow:
            report.approval_summary = self._summarize_approval(approval_flow)

        if canary_stages:
            report.canary_summary = self._summarize_canary(canary_stages)

        if rollback_performed and rollback_details:
            report.rollback_summary = rollback_details

        report.compliance_notes = self._generate_compliance_notes(
            pre_check_report, approval_flow, rollback_performed
        )

        self._save_report(report)

        return report

    def _summarize_pre_check(self, report: PreCheckReport) -> Dict[str, Any]:
        summary = {
            "overall_passed": report.overall_passed,
            "check_count": len(report.results),
            "passed_count": 0,
            "failed_count": 0,
            "warning_count": 0,
            "skipped_count": 0,
            "details": [],
        }

        for result in report.results:
            if result.status.value == "pass":
                summary["passed_count"] += 1
            elif result.status.value == "fail":
                summary["failed_count"] += 1
            elif result.status.value == "warning":
                summary["warning_count"] += 1
            else:
                summary["skipped_count"] += 1

            summary["details"].append({
                "check_name": result.check_name,
                "status": result.status.value,
                "score": result.score,
                "threshold": result.threshold,
                "message": result.message,
                "remediation": result.remediation,
            })

        return summary

    def _summarize_approval(self, flow: ApprovalFlow) -> Dict[str, Any]:
        summary = {
            "release_type": flow.release_type.value,
            "is_completed": flow.is_completed,
            "is_rejected": flow.is_rejected,
            "total_levels": len(set(r.level for r in flow.records)),
            "approval_records": [],
        }

        for record in flow.records:
            summary["approval_records"].append({
                "level": record.level,
                "role": record.role,
                "action": record.action.value,
                "comment": record.comment,
                "timestamp": record.timestamp,
                "is_post_sign": record.is_post_sign,
            })

        if flow.release_type == ReleaseType.HOTFIX:
            summary["hotfix_reason"] = flow.hotfix_reason
            summary["deviation_report_id"] = flow.deviation_report_id
            post_signed = [r for r in flow.records if r.is_post_sign]
            summary["post_sign_count"] = len(post_signed)

        return summary

    def _summarize_canary(self, stages: List[CanaryStage]) -> Dict[str, Any]:
        summary = {
            "total_stages": len(stages),
            "passed_stages": 0,
            "failed_stages": 0,
            "stage_details": [],
        }

        for stage in stages:
            detail = {
                "name": stage.name,
                "weight_percent": stage.weight_percent,
                "status": stage.status,
                "duration_minutes": stage.duration_minutes,
                "metrics_summary": {},
            }

            if stage.metrics:
                total = stage.metrics.get("total_requests", 0)
                errors = stage.metrics.get("error_count", 0)
                total_latency = stage.metrics.get("total_latency_ms", 0)
                detail["metrics_summary"] = {
                    "total_requests": total,
                    "error_rate": round(errors / total, 6) if total > 0 else 0,
                    "avg_latency_ms": round(total_latency / total, 2) if total > 0 else 0,
                    "max_latency_ms": stage.metrics.get("max_latency_ms", 0),
                    "temp_anomalies": stage.metrics.get("temp_anomalies", 0),
                }

            if stage.status == "passed":
                summary["passed_stages"] += 1
            elif stage.status == "failed":
                summary["failed_stages"] += 1

            summary["stage_details"].append(detail)

        return summary

    def _generate_compliance_notes(
        self,
        pre_check_report: Optional[PreCheckReport],
        approval_flow: Optional[ApprovalFlow],
        rollback_performed: bool,
    ) -> List[str]:
        notes = []

        if pre_check_report and not pre_check_report.overall_passed:
            failed = [r for r in pre_check_report.results if r.status.value == "fail"]
            notes.append(
                f"GSP合规提醒: 发布前置校验存在{len(failed)}项未通过检查，"
                f"需记录偏差并评估合规风险"
            )

        if approval_flow:
            if approval_flow.release_type == ReleaseType.HOTFIX:
                if not approval_flow.hotfix_reason:
                    notes.append("合规偏差: 紧急热修复缺少紧急原因记录")
                if not approval_flow.deviation_report_id:
                    notes.append("合规偏差: 紧急热修复缺少偏差报告编号")

                post_signed = [r for r in approval_flow.records if r.is_post_sign]
                if post_signed:
                    notes.append(
                        f"事后补签记录: {len(post_signed)}项审批为事后补签，"
                        f"需在合规档案中标注"
                    )

        if rollback_performed:
            notes.append(
                "版本回滚已执行: 本次发布触发回滚，需按照GSP要求填写回滚原因报告"
            )
            notes.append(
                "数据完整性确认: 回滚后需验证温湿度监测数据连续性与完整性"
            )

        if not notes:
            notes.append("本次发布全流程符合GSP合规要求，无偏差项")

        return notes

    def _save_report(self, report: ReviewReport):
        os.makedirs(self.report_output_dir, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"review_report_{report.release_id}_{timestamp}"

        if self.report_format == "html":
            self._save_html_report(report, filename)
        else:
            self._save_json_report(report, filename)

    def _save_html_report(self, report: ReviewReport, filename: str):
        filepath = os.path.join(self.report_output_dir, f"{filename}.html")

        html = self._build_html_report(report)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)

        self.logger.info(f"复盘报表已保存: {filepath}")

    def _save_json_report(self, report: ReviewReport, filename: str):
        filepath = os.path.join(self.report_output_dir, f"{filename}.json")

        data = {
            "release_id": report.release_id,
            "version": report.version,
            "release_type": report.release_type.value,
            "pre_check_summary": report.pre_check_summary,
            "approval_summary": report.approval_summary,
            "canary_summary": report.canary_summary,
            "rollback_summary": report.rollback_summary,
            "compliance_notes": report.compliance_notes,
            "generated_at": report.generated_at,
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

        self.logger.info(f"复盘报表已保存: {filepath}")

    def _build_html_report(self, report: ReviewReport) -> str:
        pre_check_html = self._render_pre_check_html(report.pre_check_summary)
        approval_html = self._render_approval_html(report.approval_summary)
        canary_html = self._render_canary_html(report.canary_summary)
        rollback_html = self._render_rollback_html(report.rollback_summary)
        compliance_html = self._render_compliance_html(report.compliance_notes)

        return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>发布复盘报表 - {report.release_id}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Microsoft YaHei', sans-serif; background: #f5f7fa; color: #333; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ background: linear-gradient(135deg, #1a5276, #2980b9); color: white; padding: 30px; border-radius: 8px 8px 0 0; }}
        .header h1 {{ font-size: 24px; margin-bottom: 10px; }}
        .header .meta {{ font-size: 14px; opacity: 0.9; }}
        .section {{ background: white; margin: 16px 0; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); overflow: hidden; }}
        .section-title {{ background: #f8f9fa; padding: 16px 24px; font-size: 18px; font-weight: bold; border-bottom: 2px solid #2980b9; color: #1a5276; }}
        .section-body {{ padding: 24px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th, td {{ padding: 12px 16px; text-align: left; border-bottom: 1px solid #eee; }}
        th {{ background: #f8f9fa; font-weight: 600; color: #555; }}
        .badge {{ display: inline-block; padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: 600; }}
        .badge-pass {{ background: #d5f5e3; color: #1e8449; }}
        .badge-fail {{ background: #fadbd8; color: #c0392b; }}
        .badge-warn {{ background: #fef9e7; color: #b7950b; }}
        .badge-info {{ background: #d6eaf8; color: #2471a3; }}
        .metric-card {{ display: inline-block; background: #f8f9fa; padding: 16px 24px; border-radius: 8px; margin: 8px; text-align: center; }}
        .metric-value {{ font-size: 28px; font-weight: bold; color: #1a5276; }}
        .metric-label {{ font-size: 12px; color: #7f8c8d; margin-top: 4px; }}
        .compliance-item {{ padding: 12px 16px; margin: 8px 0; border-left: 4px solid #2980b9; background: #f8f9fa; border-radius: 0 4px 4px 0; }}
        .compliance-warning {{ border-left-color: #e74c3c; }}
        .footer {{ text-align: center; padding: 20px; color: #7f8c8d; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>医药冷链温湿度监控系统 - 发布复盘报表</h1>
            <div class="meta">
                发布单号: {report.release_id} | 版本: {report.version} |
                发布类型: {'常规迭代' if report.release_type == ReleaseType.ROUTINE else '紧急热修复'} |
                生成时间: {report.generated_at}
            </div>
        </div>

        {pre_check_html}
        {approval_html}
        {canary_html}
        {rollback_html}
        {compliance_html}

        <div class="footer">
            本报表由医药冷链温湿度监控系统版本发布与智能回滚自动化平台自动生成 | 符合GSP合规审计要求
        </div>
    </div>
</body>
</html>"""

    def _render_pre_check_html(self, summary: Dict[str, Any]) -> str:
        if not summary:
            return ""

        details_rows = ""
        for d in summary.get("details", []):
            badge_class = {
                "pass": "badge-pass",
                "fail": "badge-fail",
                "warning": "badge-warn",
                "skipped": "badge-info",
            }.get(d["status"], "badge-info")
            details_rows += f"""
                <tr>
                    <td>{d['check_name']}</td>
                    <td><span class="badge {badge_class}">{d['status'].upper()}</span></td>
                    <td>{d['score']:.4f}</td>
                    <td>{d['threshold']:.4f}</td>
                    <td>{d['message']}</td>
                    <td>{d.get('remediation', '-')}</td>
                </tr>"""

        overall_badge = "badge-pass" if summary.get("overall_passed") else "badge-fail"
        overall_text = "全部通过" if summary.get("overall_passed") else "存在未通过项"

        return f"""
        <div class="section">
            <div class="section-title">一、发布前置校验结果</div>
            <div class="section-body">
                <div style="margin-bottom:16px;">
                    <span class="badge {overall_badge}" style="font-size:16px;">综合结果: {overall_text}</span>
                    <span style="margin-left:20px;">通过: {summary.get('passed_count',0)} | 未通过: {summary.get('failed_count',0)} | 告警: {summary.get('warning_count',0)} | 跳过: {summary.get('skipped_count',0)}</span>
                </div>
                <table>
                    <thead><tr><th>检查项</th><th>状态</th><th>得分</th><th>阈值</th><th>详情</th><th>修复建议</th></tr></thead>
                    <tbody>{details_rows}</tbody>
                </table>
            </div>
        </div>"""

    def _render_approval_html(self, summary: Dict[str, Any]) -> str:
        if not summary:
            return ""

        rows = ""
        for r in summary.get("approval_records", []):
            badge_class = {"approve": "badge-pass", "reject": "badge-fail", "pending": "badge-info"}.get(
                r["action"], "badge-info"
            )
            post_sign_tag = ' <span class="badge badge-warn">事后补签</span>' if r.get("is_post_sign") else ""
            rows += f"""
                <tr>
                    <td>第{r['level']}级</td>
                    <td>{r['role']}</td>
                    <td><span class="badge {badge_class}">{r['action'].upper()}</span>{post_sign_tag}</td>
                    <td>{r.get('comment', '-')}</td>
                    <td>{r.get('timestamp', '-')}</td>
                </tr>"""

        hotfix_info = ""
        if summary.get("release_type") == "hotfix":
            hotfix_info = f"""
                <div style="margin-bottom:12px; padding:12px; background:#fef9e7; border-left:4px solid #f39c12; border-radius:4px;">
                    <strong>紧急热修复信息</strong><br>
                    紧急原因: {summary.get('hotfix_reason', '未记录')}<br>
                    偏差报告编号: {summary.get('deviation_report_id', '未关联')}<br>
                    事后补签数量: {summary.get('post_sign_count', 0)}
                </div>"""

        return f"""
        <div class="section">
            <div class="section-title">二、审批流转记录</div>
            <div class="section-body">
                {hotfix_info}
                <table>
                    <thead><tr><th>审批级别</th><th>审批角色</th><th>审批结果</th><th>审批意见</th><th>审批时间</th></tr></thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>
        </div>"""

    def _render_canary_html(self, summary: Dict[str, Any]) -> str:
        if not summary:
            return ""

        rows = ""
        for s in summary.get("stage_details", []):
            badge_class = {"passed": "badge-pass", "failed": "badge-fail", "pending": "badge-info", "running": "badge-warn"}.get(
                s["status"], "badge-info"
            )
            metrics = s.get("metrics_summary", {})
            metrics_str = ""
            if metrics:
                metrics_str = (
                    f"请求量: {metrics.get('total_requests', 0)}, "
                    f"错误率: {metrics.get('error_rate', 0):.4%}, "
                    f"平均延迟: {metrics.get('avg_latency_ms', 0):.0f}ms"
                )
            rows += f"""
                <tr>
                    <td>{s['name']}</td>
                    <td>{s['weight_percent']}%</td>
                    <td><span class="badge {badge_class}">{s['status'].upper()}</span></td>
                    <td>{s.get('duration_minutes', 0)}分钟</td>
                    <td>{metrics_str or '-'}</td>
                </tr>"""

        return f"""
        <div class="section">
            <div class="section-title">三、灰度发布与熔断机制</div>
            <div class="section-body">
                <div style="margin-bottom:16px;">
                    <div class="metric-card"><div class="metric-value">{summary.get('total_stages', 0)}</div><div class="metric-label">总阶段数</div></div>
                    <div class="metric-card"><div class="metric-value">{summary.get('passed_stages', 0)}</div><div class="metric-label">通过阶段</div></div>
                    <div class="metric-card"><div class="metric-value">{summary.get('failed_stages', 0)}</div><div class="metric-label">失败阶段</div></div>
                </div>
                <table>
                    <thead><tr><th>阶段</th><th>流量比例</th><th>状态</th><th>持续时间</th><th>关键指标</th></tr></thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>
        </div>"""

    def _render_rollback_html(self, summary: Optional[Dict[str, Any]]) -> str:
        if not summary:
            return """
            <div class="section">
                <div class="section-title">四、回滚记录</div>
                <div class="section-body">
                    <p style="color:#7f8c8d;">本次发布未触发回滚</p>
                </div>
            </div>"""

        return f"""
        <div class="section">
            <div class="section-title">四、回滚记录</div>
            <div class="section-body">
                <div style="padding:12px; background:#fadbd8; border-left:4px solid #e74c3c; border-radius:4px;">
                    <strong>回滚已执行</strong><br>
                    回滚版本: {summary.get('from_version', '-')} → {summary.get('to_version', '-')}<br>
                    回滚原因: {summary.get('reason', '-')}<br>
                    健康检查: {'通过' if summary.get('health_check_passed') else '未通过'}<br>
                    快照校验: {'通过' if summary.get('snapshot_verified') else '未通过'}
                </div>
            </div>
        </div>"""

    def _render_compliance_html(self, notes: List[str]) -> str:
        items = ""
        for note in notes:
            is_warning = "偏差" in note or "回滚" in note or "未通过" in note
            css_class = "compliance-item compliance-warning" if is_warning else "compliance-item"
            items += f'<div class="{css_class}">{note}</div>'

        return f"""
        <div class="section">
            <div class="section-title">五、合规审计说明</div>
            <div class="section-body">
                {items}
            </div>
        </div>"""
