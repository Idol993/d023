#!/usr/bin/env python3
import sys
import os
import yaml
import json
import argparse
import uuid
import hashlib
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.logger import setup_logger
from utils.db import Database
from utils.notify import Notifier
from modules.pre_check import PreCheckEngine
from modules.approval import ApprovalEngine, ApprovalAction
from modules.canary_release import CanaryReleaseEngine
from modules.audit_report import AuditEngine
from models.schemas import (
    ReleaseType,
    ReleaseStatus,
    ReleaseRecord,
    RollbackSnapshot,
)


class ReleasePlatform:
    def __init__(self, config_path: str = "config/settings.yaml"):
        self.config = self._load_config(config_path)
        self.logger = setup_logger("release_platform", self.config.get("logging", {}))
        self.db = Database(self.config.get("database", {}))
        self.notifier = Notifier(self.config.get("notification", {}))
        self.pre_check_engine = PreCheckEngine(self.config.get("pre_check", {}))
        self.approval_engine = ApprovalEngine(self.config.get("approval", {}))
        self.canary_engine = CanaryReleaseEngine(self.config.get("canary_release", {}))
        self.audit_engine = AuditEngine(self.config.get("audit", {}), self.db)

        self.logger.info("=" * 60)
        self.logger.info("医药冷链温湿度监控系统 - 版本发布与智能回滚自动化平台 初始化完成")
        self.logger.info("=" * 60)

    def _load_config(self, config_path: str) -> dict:
        abs_path = os.path.abspath(config_path)
        if not os.path.exists(abs_path):
            print(f"配置文件不存在: {abs_path}")
            sys.exit(1)
        with open(abs_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)

    def _generate_release_id(self) -> str:
        date_str = datetime.now().strftime("%Y%m%d%H%M%S")
        short_uuid = uuid.uuid4().hex[:8]
        return f"REL-{date_str}-{short_uuid}"

    def create_release(
        self,
        version: str,
        previous_version: str,
        release_type: str,
        applicant: str,
        description: str = "",
        hotfix_reason: str = "",
        deviation_report_id: str = "",
    ) -> ReleaseRecord:
        rt = ReleaseType.ROUTINE if release_type == "routine" else ReleaseType.HOTFIX

        release_id = self._generate_release_id()
        record = ReleaseRecord(
            release_id=release_id,
            version=version,
            previous_version=previous_version,
            release_type=rt,
            applicant=applicant,
            description=description,
        )

        self.audit_engine.log_action(
            release_id=release_id,
            action="release_created",
            actor=applicant,
            details={
                "version": version,
                "previous_version": previous_version,
                "release_type": rt.value,
                "description": description,
            },
            electronic_signature=f"SIG-{applicant}-{uuid.uuid4().hex[:12]}",
        )

        self.notifier.notify_release_created(release_id, version, rt.value)
        self._save_record(record)

        self.logger.info(
            f"发布申请已创建 [id={release_id}, version={version}, type={rt.value}]"
        )
        return record

    def run_pre_check(self, release_id: str) -> dict:
        self.logger.info(f"开始发布前置校验 [release_id={release_id}]")

        record_data = self.db.get_release_record(release_id)
        if not record_data:
            return {"success": False, "message": f"发布单不存在: {release_id}"}

        if record_data["status"] not in [ReleaseStatus.PENDING_CHECK.value, ReleaseStatus.CHECK_FAILED.value]:
            return {"success": False, "message": f"发布单状态不允许前置校验: {record_data['status']}"}

        self._update_status(release_id, ReleaseStatus.PENDING_CHECK)

        report = self.pre_check_engine.run_all_checks(release_id)

        self.audit_engine.log_action(
            release_id=release_id,
            action="pre_check_completed",
            actor="system",
            details={
                "overall_passed": report.overall_passed,
                "check_count": len(report.results),
                "failed_checks": [
                    r.check_name for r in report.results if r.status.value == "fail"
                ],
            },
            electronic_signature=f"SIG-SYSTEM-{uuid.uuid4().hex[:12]}",
        )

        if report.overall_passed:
            self._update_status(release_id, ReleaseStatus.CHECK_PASSED)
            self.notifier.notify_pre_check_result(release_id, True, "全部检查项通过")
            self.logger.info(f"前置校验通过 [release_id={release_id}]")
        else:
            self._update_status(release_id, ReleaseStatus.CHECK_FAILED)
            failed_names = [
                r.check_name for r in report.results if r.status.value == "fail"
            ]
            self.notifier.notify_pre_check_result(
                release_id, False, f"未通过项: {', '.join(failed_names)}"
            )
            self.logger.warning(f"前置校验未通过 [release_id={release_id}]: {failed_names}")

        self._save_pre_check_report(release_id, report)

        return {
            "success": report.overall_passed,
            "release_id": release_id,
            "overall_passed": report.overall_passed,
            "results": [
                {
                    "check_name": r.check_name,
                    "status": r.status.value,
                    "score": r.score,
                    "threshold": r.threshold,
                    "message": r.message,
                    "remediation": r.remediation,
                }
                for r in report.results
            ],
        }

    def init_approval(self, release_id: str, hotfix_reason: str = "", deviation_report_id: str = "") -> dict:
        record_data = self.db.get_release_record(release_id)
        if not record_data:
            return {"success": False, "message": f"发布单不存在: {release_id}"}

        if record_data["status"] != ReleaseStatus.CHECK_PASSED.value:
            return {"success": False, "message": "前置校验未通过，无法进入审批环节"}

        rt = ReleaseType(record_data["release_type"])

        flow = self.approval_engine.create_flow(
            release_id=release_id,
            release_type=rt,
            hotfix_reason=hotfix_reason,
            deviation_report_id=deviation_report_id,
        )

        self._update_status(release_id, ReleaseStatus.PENDING_APPROVAL)

        first_record = flow.records[0] if flow.records else None
        if first_record:
            self.notifier.notify_approval_required(
                release_id, first_record.role, first_record.level
            )

        self.audit_engine.log_action(
            release_id=release_id,
            action="approval_initiated",
            actor="system",
            details={"release_type": rt.value, "flow_type": "serial" if rt == ReleaseType.ROUTINE else "parallel"},
            electronic_signature=f"SIG-SYSTEM-{uuid.uuid4().hex[:12]}",
        )

        self._save_approval_flow(release_id, flow)

        return {
            "success": True,
            "release_id": release_id,
            "flow_status": self.approval_engine.get_flow_status(flow),
        }

    def process_approval(
        self,
        release_id: str,
        level: int,
        role: str,
        action: str,
        approver: str,
        comment: str = "",
        is_post_sign: bool = False,
    ) -> dict:
        flow = self._load_approval_flow(release_id)
        if not flow:
            return {"success": False, "message": f"审批流不存在: {release_id}"}

        approval_action = ApprovalAction.APPROVE if action == "approve" else ApprovalAction.REJECT

        result = self.approval_engine.process_approval(
            flow=flow,
            level=level,
            role=role,
            action=approval_action,
            approver=approver,
            comment=comment,
            is_post_sign=is_post_sign,
        )

        self.audit_engine.log_action(
            release_id=release_id,
            action=f"approval_{action}",
            actor=approver,
            details={
                "level": level,
                "role": role,
                "comment": comment,
                "is_post_sign": is_post_sign,
            },
            electronic_signature=f"SIG-{approver}-{uuid.uuid4().hex[:12]}",
        )

        if result.get("flow_completed"):
            self._update_status(release_id, ReleaseStatus.APPROVAL_PASSED)
            self.notifier.notify_approval_result(release_id, True, "全部")
            self.audit_engine.log_action(
                release_id=release_id,
                action="approval_completed",
                actor="system",
                details={
                    "release_type": flow.release_type.value,
                    "total_levels": len(flow.records),
                },
                electronic_signature=f"SIG-SYSTEM-{uuid.uuid4().hex[:12]}",
            )
        elif result.get("flow_rejected"):
            self._update_status(release_id, ReleaseStatus.APPROVAL_REJECTED)
            self.notifier.notify_approval_result(release_id, False, role)
        else:
            next_role = result.get("next_role", "")
            if next_role:
                self.notifier.notify_approval_required(release_id, next_role, result.get("next_level", level + 1))
            self.notifier.notify_approval_result(release_id, True, role)

        self._save_approval_flow(release_id, flow)

        return {
            "success": result["success"],
            "message": result.get("message", ""),
            "release_id": release_id,
            "result": result,
        }

    def start_canary_release(self, release_id: str) -> dict:
        try:
            return self._execute_canary_release(release_id)
        except Exception as e:
            self.logger.error(f"灰度发布异常 [release_id={release_id}]: {e}", exc_info=True)
            current_record = self.db.get_release_record(release_id)
            return {
                "success": False,
                "release_id": release_id,
                "final_status": current_record["status"] if current_record else "unknown",
                "rollback_performed": False,
                "canary_summary": {},
                "report_generated": False,
                "error": str(e),
            }

    def _execute_canary_release(self, release_id: str) -> dict:
        record_data = self.db.get_release_record(release_id)
        if not record_data:
            return {"success": False, "message": f"发布单不存在: {release_id}", "final_status": "unknown"}

        if record_data["status"] != ReleaseStatus.APPROVAL_PASSED.value:
            return {"success": False, "message": "审批未通过，无法启动灰度发布", "final_status": record_data["status"]}

        self._update_status(release_id, ReleaseStatus.CANARY_DEPLOYING)

        snapshot = self.canary_engine.create_rollback_snapshot(
            version=record_data["previous_version"],
            release_id=release_id,
            config_data={"version": record_data["previous_version"], "release_id": release_id},
        )
        self.db.save_rollback_snapshot(
            release_id=release_id,
            version=snapshot.version,
            config_snapshot=snapshot.config_snapshot,
            checksum=snapshot.checksum,
        )

        stages = self.canary_engine.create_canary_stages()
        circuit_breaker = self._create_circuit_breaker()

        self.audit_engine.log_action(
            release_id=release_id,
            action="canary_started",
            actor="system",
            details={"stages": len(stages), "snapshot_version": snapshot.version},
            electronic_signature=f"SIG-SYSTEM-{uuid.uuid4().hex[:12]}",
        )

        self.notifier.notify_canary_progress(release_id, "灰度发布启动", "started")

        rollback_performed = False
        rollback_details = None
        failed_stage = None

        for i, stage in enumerate(stages):
            self.notifier.notify_canary_progress(release_id, stage.name, "started")

            stage_result = self.canary_engine.execute_canary_stage(
                stage=stage,
                circuit_breaker=circuit_breaker,
                release_id=release_id,
            )

            if not stage_result["success"]:
                failed_stage = stage.name
                self._update_status(release_id, ReleaseStatus.CANARY_FAILED)

                self.audit_engine.log_action(
                    release_id=release_id,
                    action="canary_failed",
                    actor="system",
                    details={"failed_stage": failed_stage, "reason": stage_result.get("message", "")},
                    electronic_signature=f"SIG-SYSTEM-{uuid.uuid4().hex[:12]}",
                )

                self.notifier.notify_circuit_breaker_triggered(
                    release_id, stage_result.get("message", "熔断触发")
                )

                if self.canary_engine.rollback_config.get("auto_rollback_enabled", True):
                    self.logger.warning(f"自动回滚触发 [release_id={release_id}]")
                    self._update_status(release_id, ReleaseStatus.ROLLING_BACK)

                    rollback_result = self.canary_engine.execute_rollback(
                        release_id=release_id,
                        from_version=record_data["version"],
                        snapshot=snapshot,
                        reason=f"灰度阶段[{failed_stage}]熔断触发: {stage_result.get('message', '')}",
                    )

                    if rollback_result["success"]:
                        self._update_status(release_id, ReleaseStatus.ROLLED_BACK)
                        rollback_performed = True
                        rollback_details = rollback_result
                        self.notifier.notify_rollback(
                            release_id, record_data["version"], snapshot.version
                        )
                    else:
                        self.logger.error(f"回滚失败 [release_id={release_id}]，需要人工介入")

                    self.audit_engine.log_action(
                        release_id=release_id,
                        action="rollback_executed" if rollback_result["success"] else "rollback_failed",
                        actor="system",
                        details=rollback_result,
                        electronic_signature=f"SIG-SYSTEM-{uuid.uuid4().hex[:12]}",
                    )

                break
            else:
                self.notifier.notify_canary_progress(release_id, stage.name, "passed")

        if not failed_stage:
            self._update_status(release_id, ReleaseStatus.FULLY_RELEASED)
            self.notifier.notify_release_completed(release_id, record_data["version"])

            self.audit_engine.log_action(
                release_id=release_id,
                action="release_completed",
                actor="system",
                details={"version": record_data["version"]},
                electronic_signature=f"SIG-SYSTEM-{uuid.uuid4().hex[:12]}",
            )

        canary_summary = self.canary_engine.get_canary_summary(stages)

        report = self.audit_engine.generate_review_report(
            release_id=release_id,
            version=record_data["version"],
            release_type=ReleaseType(record_data["release_type"]),
            pre_check_report=self._load_pre_check_report(release_id),
            approval_flow=self._load_approval_flow(release_id),
            canary_stages=stages,
            rollback_performed=rollback_performed,
            rollback_details=rollback_details,
        )

        self.audit_engine.log_action(
            release_id=release_id,
            action="review_report_generated",
            actor="system",
            details={"report_generated": True},
            electronic_signature=f"SIG-SYSTEM-{uuid.uuid4().hex[:12]}",
        )

        return {
            "success": not failed_stage,
            "release_id": release_id,
            "final_status": self.db.get_release_record(release_id)["status"],
            "rollback_performed": rollback_performed,
            "canary_summary": canary_summary,
            "report_generated": True,
        }

    def get_release_status(self, release_id: str) -> dict:
        record_data = self.db.get_release_record(release_id)
        if not record_data:
            return {"success": False, "message": f"发布单不存在: {release_id}"}

        audit_logs = self.audit_engine.get_audit_trail(release_id)
        integrity = self.audit_engine.verify_audit_integrity(
            release_id,
            current_status=record_data.get("status"),
        )

        return {
            "success": True,
            "release": record_data,
            "audit_log_count": len(audit_logs),
            "audit_integrity": integrity,
        }

    def _update_status(self, release_id: str, status: ReleaseStatus):
        try:
            record_data = self.db.get_release_record(release_id)
            if record_data:
                record_data["status"] = status.value
                record_data["updated_at"] = datetime.now().isoformat()
                if status in [ReleaseStatus.FULLY_RELEASED, ReleaseStatus.ROLLED_BACK, ReleaseStatus.APPROVAL_REJECTED]:
                    record_data["completed_at"] = datetime.now().isoformat()
                self.db.save_release_record(record_data)
                self.logger.debug(f"状态已更新 [release_id={release_id}]: {status.value}")
        except Exception as e:
            self.logger.error(f"状态更新失败 [release_id={release_id}, status={status.value}]: {e}")

    def _save_record(self, record: ReleaseRecord):
        data = {
            "release_id": record.release_id,
            "version": record.version,
            "previous_version": record.previous_version,
            "release_type": record.release_type.value,
            "status": record.status.value,
            "applicant": record.applicant,
            "description": record.description,
            "created_at": record.created_at,
            "updated_at": record.updated_at,
        }
        self.db.save_release_record(data)

    def _save_pre_check_report(self, release_id: str, report):
        record_data = self.db.get_release_record(release_id)
        if record_data:
            report_data = {
                "overall_passed": report.overall_passed,
                "results": [
                    {
                        "check_name": r.check_name,
                        "status": r.status.value,
                        "score": r.score,
                        "threshold": r.threshold,
                        "message": r.message,
                    }
                    for r in report.results
                ],
            }
            record_data["pre_check_report"] = json.dumps(report_data, ensure_ascii=False)
            self.db.save_release_record(record_data)

    def _load_pre_check_report(self, release_id: str):
        record_data = self.db.get_release_record(release_id)
        if record_data and record_data.get("pre_check_report"):
            data = json.loads(record_data["pre_check_report"])
            from models.schemas import PreCheckReport, CheckResult, CheckResultStatus
            report = PreCheckReport(release_id=release_id, overall_passed=data["overall_passed"])
            for r in data.get("results", []):
                report.add_result(CheckResult(
                    check_name=r["check_name"],
                    status=CheckResultStatus(r["status"]),
                    score=r["score"],
                    threshold=r["threshold"],
                    message=r["message"],
                ))
            return report
        return None

    def _save_approval_flow(self, release_id: str, flow):
        record_data = self.db.get_release_record(release_id)
        if record_data:
            flow_data = {
                "release_type": flow.release_type.value,
                "is_completed": flow.is_completed,
                "is_rejected": flow.is_rejected,
                "current_level": flow.current_level,
                "hotfix_reason": flow.hotfix_reason,
                "deviation_report_id": flow.deviation_report_id,
                "records": [
                    {
                        "level": r.level,
                        "role": r.role,
                        "approver": r.approver,
                        "action": r.action.value,
                        "comment": r.comment,
                        "timestamp": r.timestamp,
                        "is_post_sign": r.is_post_sign,
                        "timeout_minutes": r.timeout_minutes,
                        "deadline": r.deadline,
                    }
                    for r in flow.records
                ],
            }
            record_data["approval_flow"] = json.dumps(flow_data, ensure_ascii=False)
            self.db.save_release_record(record_data)

    def _load_approval_flow(self, release_id: str):
        record_data = self.db.get_release_record(release_id)
        if record_data and record_data.get("approval_flow"):
            data = json.loads(record_data["approval_flow"])
            from models.schemas import ApprovalFlow, ApprovalRecord, ApprovalAction, ReleaseType
            flow = ApprovalFlow(
                release_id=release_id,
                release_type=ReleaseType(data["release_type"]),
                is_completed=data["is_completed"],
                is_rejected=data["is_rejected"],
                current_level=data["current_level"],
                hotfix_reason=data.get("hotfix_reason", ""),
                deviation_report_id=data.get("deviation_report_id", ""),
            )
            flow.records = [
                ApprovalRecord(
                    level=r["level"],
                    role=r["role"],
                    approver=r["approver"],
                    action=ApprovalAction(r["action"]),
                    comment=r.get("comment", ""),
                    timestamp=r.get("timestamp"),
                    is_post_sign=r.get("is_post_sign", False),
                    timeout_minutes=r.get("timeout_minutes", 0),
                    deadline=r.get("deadline"),
                )
                for r in data.get("records", [])
            ]
            return flow
        return None

    def _create_circuit_breaker(self):
        from models.schemas import CircuitBreaker, CircuitBreakerState
        return CircuitBreaker(state=CircuitBreakerState.CLOSED)


def run_full_release(platform: ReleasePlatform, args: argparse.Namespace) -> dict:
    if args.type == "hotfix":
        if not args.hotfix_reason or not args.hotfix_reason.strip():
            print("\n[ERROR] 紧急热修复发布必须填写紧急原因 (--hotfix-reason)")
            print("  请补充紧急原因后重新提交发布申请。\n")
            return {"success": False, "message": "缺少紧急原因"}
        if not args.deviation_report or not args.deviation_report.strip():
            print("\n[ERROR] 紧急热修复发布必须提供偏差报告编号 (--deviation-report)")
            print("  例如: --deviation-report DEV-2026-0621-001")
            print("  请在 GSP 合规系统中创建偏差报告并补充编号后继续。\n")
            return {"success": False, "message": "缺少偏差报告编号"}

    record = platform.create_release(
        version=args.version,
        previous_version=args.previous_version,
        release_type=args.type,
        applicant=args.applicant,
        description=args.description,
        hotfix_reason=args.hotfix_reason or "",
        deviation_report_id=args.deviation_report or "",
    )

    release_id = record.release_id

    print(f"\n{'='*60}")
    print(f"  发布单号: {release_id}")
    print(f"  版本: {args.version} -> {args.previous_version}")
    print(f"  类型: {'常规迭代' if args.type == 'routine' else '紧急热修复'}")
    if args.type == "hotfix":
        print(f"  紧急原因: {args.hotfix_reason}")
        print(f"  偏差报告: {args.deviation_report}")
    print(f"{'='*60}\n")

    print("[1/2] 执行发布前置校验...")
    check_result = platform.run_pre_check(release_id)
    print(f"  前置校验结果: {'通过 [PASS]' if check_result['success'] else '未通过 [FAIL]'}")
    for r in check_result.get("results", []):
        icon = "[PASS]" if r["status"] == "pass" else "[FAIL]" if r["status"] == "fail" else "[WARN]"
        print(f"    {icon} {r['check_name']}: {r['message']}")

    if not check_result["success"]:
        print("\n前置校验未通过，发布流程终止。请修复问题后重新提交。")
        return check_result

    print("\n[2/2] 初始化审批流...")
    init_result = platform.init_approval(
        release_id,
        hotfix_reason=args.hotfix_reason or "",
        deviation_report_id=args.deviation_report or "",
    )
    print(f"  审批流初始化: {'成功' if init_result['success'] else '失败'}")

    if not init_result["success"]:
        print(f"  错误: {init_result['message']}")
        return init_result

    print(f"\n{'='*60}")
    print(f"  发布申请已提交成功，当前处于待审批状态")
    print(f"  发布单号: {release_id}")
    print(f"  当前状态: pending_approval")
    print(f"\n  下一步操作:")
    print(f"    1. 查看审批节点详情:")
    print(f"       python main.py approvals --release-id {release_id}")
    print(f"    2. 按顺序执行审批:")

    flow = platform._load_approval_flow(release_id)
    if flow:
        step = 1
        for record in flow.records:
            if record.action.value == "pending":
                role_display = ApprovalEngine.APPROVER_MAP.get(record.role, record.role)
                print(f"       python main.py approve --release-id {release_id} --level {record.level} --role {record.role} --action approve --approver '{role_display}'")
                step += 1
    else:
        if args.type == "routine":
            print(f"       python main.py approve --release-id {release_id} --level 1 --role quality --action approve --approver '质量团队'")
            print(f"       python main.py approve --release-id {release_id} --level 2 --role logistics --action approve --approver '物流团队'")
            print(f"       python main.py approve --release-id {release_id} --level 3 --role quality_head --action approve --approver '质量负责人'")
        else:
            print(f"       python main.py approve --release-id {release_id} --level 1 --role quality --action approve --approver '质量团队'")
            print(f"       python main.py approve --release-id {release_id} --level 1 --role logistics --action approve --approver '物流团队'")
            print(f"       python main.py approve --release-id {release_id} --level 2 --role quality_head --action approve --approver '质量负责人'")
    print(f"    3. 全部审批通过后启动灰度发布:")
    print(f"       python main.py deploy --release-id {release_id}")
    print(f"{'='*60}\n")

    return {"success": True, "release_id": release_id, "status": "pending_approval"}


ACTION_DISPLAY = {
    "release_created": "创建发布单",
    "pre_check_completed": "前置校验完成",
    "approval_initiated": "审批流初始化",
    "approval_approve": "审批通过",
    "approval_reject": "审批拒绝",
    "approval_completed": "审批流完成",
    "canary_started": "灰度发布启动",
    "canary_failed": "灰度发布失败",
    "rollback_executed": "回滚执行",
    "rollback_failed": "回滚失败",
    "release_completed": "发布完成",
    "review_report_generated": "复盘报表生成",
    "reminder_sent": "催办通知",
    "audit_exported": "审计明细导出",
}

ACTION_CATEGORY = {
    "release_created": "创建",
    "pre_check_completed": "校验",
    "approval_initiated": "审批",
    "approval_approve": "审批",
    "approval_reject": "审批",
    "approval_completed": "审批",
    "canary_started": "发布",
    "canary_failed": "发布",
    "rollback_executed": "发布",
    "rollback_failed": "发布",
    "release_completed": "发布",
    "review_report_generated": "报表",
    "reminder_sent": "催办",
    "audit_exported": "审计",
}


def _build_approval_summary(flow) -> list:
    summary = []
    if not flow:
        return summary
    for r in flow.records:
        action_val = r.action.value
        summary.append({
            "level": r.level,
            "role": r.role,
            "role_display": ApprovalEngine.APPROVER_MAP.get(r.role, r.role),
            "approver": r.approver,
            "action": action_val,
            "timestamp": r.timestamp or "",
            "comment": r.comment or "",
            "timeout_minutes": r.timeout_minutes,
            "deadline": r.deadline or "",
            "overdue": _is_deadline_overdue(r.deadline) if r.deadline else False,
        })
    return summary


def _build_canary_summary(canary_record_data: dict) -> list:
    summary = []
    if not canary_record_data or not canary_record_data.get("canary_stages"):
        return summary
    try:
        stages = json.loads(canary_record_data["canary_stages"])
        for s in stages:
            summary.append({
                "name": s.get("name", ""),
                "weight_percent": s.get("weight_percent", 0),
                "status": s.get("status", ""),
                "started_at": s.get("started_at", "") or "",
                "completed_at": s.get("completed_at", "") or "",
            })
    except (json.JSONDecodeError, TypeError):
        pass
    return summary


def run_audit_export(platform: ReleasePlatform, args: argparse.Namespace) -> dict:
    release_id = args.release_id
    export_format = args.format

    record_data = platform.db.get_release_record(release_id)
    if not record_data:
        print(f"[ERROR] 发布单不存在: {release_id}")
        return {"success": False}

    logs = platform.audit_engine.get_audit_trail(release_id)
    if not logs:
        print(f"[WARN] 发布单无审计日志: {release_id}")
        return {"success": False}

    sorted_logs = sorted(logs, key=lambda x: x.get("timestamp", ""))

    filtered_logs = sorted_logs
    if args.action:
        filter_actions = [a.strip() for a in args.action.split(",") if a.strip()]
        if filter_actions:
            filtered_logs = [log for log in filtered_logs if log.get("action") in filter_actions]

    if args.since or args.until:
        def _parse_iso(s):
            if not s:
                return None
            try:
                from datetime import datetime as _dt
                return _dt.fromisoformat(s.replace("Z", "+00:00"))
            except Exception:
                return None

        since_dt = _parse_iso(args.since)
        until_dt = _parse_iso(args.until)
        def _in_range(ts):
            if not ts:
                return True
            try:
                from datetime import datetime as _dt
                cur = _dt.fromisoformat(ts.replace("Z", "+00:00"))
            except Exception:
                return True
            if since_dt and cur < since_dt:
                return False
            if until_dt and cur > until_dt:
                return False
            return True
        filtered_logs = [log for log in filtered_logs if _in_range(log.get("timestamp", ""))]

    audit_entries = []
    for log in filtered_logs:
        action = log.get("action", "")
        entry = {
            "timestamp": log.get("timestamp", ""),
            "action": action,
            "action_display": ACTION_DISPLAY.get(action, action),
            "category": ACTION_CATEGORY.get(action, "其他"),
            "actor": log.get("actor", ""),
            "details": log.get("details", {}),
            "electronic_signature": log.get("electronic_signature", ""),
        }
        audit_entries.append(entry)

    output_dir = platform.audit_engine.report_output_dir
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    flow = platform._load_approval_flow(release_id)
    approval_summary = _build_approval_summary(flow)
    canary_summary = _build_canary_summary(record_data)
    integrity = platform.audit_engine.verify_audit_integrity(
        release_id, current_status=record_data.get("status")
    )

    export_meta = {
        "filters": {
            "action": args.action or "",
            "since": args.since or "",
            "until": args.until or "",
        },
        "approval_summary": approval_summary,
        "canary_summary": canary_summary,
        "audit_integrity": integrity,
    }

    filepath = ""
    if export_format == "json":
        filepath = os.path.join(output_dir, f"audit_{release_id}_{timestamp}.json")
        export_data = {
            "release_id": release_id,
            "version": record_data.get("version", ""),
            "previous_version": record_data.get("previous_version", ""),
            "release_type": record_data.get("release_type", ""),
            "status": record_data.get("status", ""),
            "applicant": record_data.get("applicant", ""),
            "created_at": record_data.get("created_at", ""),
            "exported_at": datetime.now().isoformat(),
            "total_entries": len(audit_entries),
            "meta": export_meta,
            "audit_trail": audit_entries,
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(export_data, f, ensure_ascii=False, indent=2, default=str)
    else:
        filepath = os.path.join(output_dir, f"audit_{release_id}_{timestamp}.html")
        html = _build_audit_html(release_id, record_data, audit_entries, export_meta)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)

    export_details = {
        "format": export_format,
        "filepath": os.path.abspath(filepath),
        "total_entries": len(audit_entries),
        "filters": {
            "action": args.action or "",
            "since": args.since or "",
            "until": args.until or "",
        },
    }
    platform.audit_engine.log_action(
        release_id=release_id,
        action="audit_exported",
        actor=args.operator or "system",
        details=export_details,
        electronic_signature=f"SIG-AUDEXP-{uuid.uuid4().hex[:12]}",
    )

    print(f"\n审计明细导出完成")
    print(f"  发布单号: {release_id}")
    print(f"  导出格式: {export_format.upper()}")
    print(f"  审计条目: {len(audit_entries)} 条")
    if args.action or args.since or args.until:
        applied = []
        if args.action: applied.append(f"action={args.action}")
        if args.since: applied.append(f"since={args.since}")
        if args.until: applied.append(f"until={args.until}")
        print(f"  筛选条件: {', '.join(applied)}")
    integrity_valid = integrity.get("integrity_valid", False)
    print(f"  审计完整性: {'通过 [PASS]' if integrity_valid else '未通过 [FAIL]'}")
    print(f"  文件路径: {os.path.abspath(filepath)}\n")

    return {"success": True, "filepath": filepath}


def _build_audit_html(release_id: str, record_data: dict, entries: list, meta: dict = None) -> str:
    rows = ""
    for e in entries:
        cat_badge = {
            "创建": "badge-info", "校验": "badge-pass",
            "审批": "badge-warn", "发布": "badge-info", "报表": "badge-pass",
            "催办": "badge-warn", "审计": "badge-info", "其他": "badge-info",
        }.get(e["category"], "badge-info")
        rows += f"""
            <tr>
                <td>{e['timestamp']}</td>
                <td><span class="badge {cat_badge}">{e['category']}</span></td>
                <td>{e['action_display']}</td>
                <td>{e['action']}</td>
                <td>{e['actor']}</td>
                <td>{json.dumps(e['details'], ensure_ascii=False) if e['details'] else '-'}</td>
                <td>{e['electronic_signature'] or '-'}</td>
            </tr>"""

    meta = meta or {}
    filters = meta.get("filters", {}) or {}
    filters_html = ""
    applied_filters = [(k, v) for k, v in filters.items() if v]
    if applied_filters:
        filter_items = "  ".join([f"<b>{k}</b>: {v}" for k, v in applied_filters])
        filters_html = f'<div style="background:#fff9db;padding:12px;border-radius:6px;margin-bottom:16px;">筛选条件: {filter_items}</div>'

    integrity = meta.get("audit_integrity", {}) or {}
    integrity_valid = integrity.get("integrity_valid", False)
    integrity_badge = '<span class="badge badge-pass">通过</span>' if integrity_valid else '<span class="badge badge-fail">未通过</span>'
    issues = integrity.get("issues", []) or []
    issues_html = ""
    if issues:
        issues_html = "<ul style='margin-top:8px;padding-left:18px;'>"
        for iss in issues:
            issues_html += f"<li style='color:#c0392b;margin:4px 0;'>{iss}</li>"
        issues_html += "</ul>"

    approval_summary = meta.get("approval_summary", []) or []
    approval_rows = ""
    for a in approval_summary:
        action_badge = {"approve": "badge-pass", "reject": "badge-fail", "pending": "badge-warn"}.get(a["action"], "badge-info")
        action_text = {"approve": "通过", "reject": "拒绝", "pending": "待审批"}.get(a["action"], a["action"])
        overdue_badge = ""
        if a.get("deadline") and a["action"] == "pending":
            overdue_badge = ' <span class="badge badge-fail">已超时</span>' if a.get("overdue") else ' <span class="badge badge-info">未超时</span>'
        approval_rows += f"""
            <tr>
                <td>第{a['level']}级</td>
                <td>{a['role_display']} ({a['role']})</td>
                <td><span class="badge {action_badge}">{action_text}</span>{overdue_badge}</td>
                <td>{a.get('approver', '')}</td>
                <td>{a.get('timestamp', '') or '-'}</td>
                <td>{a.get('deadline', '') or '-'}</td>
                <td>{a.get('comment', '') or '-'}</td>
            </tr>"""
    approval_html = f"""
        <div class="section">
            <div class="section-title">审批链路摘要 (共 {len(approval_summary)} 个节点)</div>
            <div class="section-body">
                <table>
                    <thead><tr><th>级别</th><th>角色</th><th>状态</th><th>审批人</th><th>审批时间</th><th>截止时间</th><th>意见</th></tr></thead>
                    <tbody>{approval_rows or '<tr><td colspan="7" style="text-align:center;color:#999;padding:20px;">暂无审批记录</td></tr>'}</tbody>
                </table>
            </div>
        </div>""" if approval_summary else ""

    canary_summary = meta.get("canary_summary", []) or []
    canary_rows = ""
    for c in canary_summary:
        st_badge = {"passed": "badge-pass", "failed": "badge-fail", "executing": "badge-warn", "pending": "badge-info"}.get(c.get("status", ""), "badge-info")
        st_text = {"passed": "通过", "failed": "失败", "executing": "执行中", "pending": "待执行"}.get(c.get("status", ""), c.get("status", "-"))
        canary_rows += f"""
            <tr>
                <td>{c.get('name', '')}</td>
                <td>{c.get('weight_percent', 0)}%</td>
                <td><span class="badge {st_badge}">{st_text}</span></td>
                <td>{c.get('started_at', '') or '-'}</td>
                <td>{c.get('completed_at', '') or '-'}</td>
            </tr>"""
    canary_html = f"""
        <div class="section">
            <div class="section-title">灰度发布阶段摘要 (共 {len(canary_summary)} 阶段)</div>
            <div class="section-body">
                <table>
                    <thead><tr><th>阶段</th><th>权重</th><th>状态</th><th>开始时间</th><th>完成时间</th></tr></thead>
                    <tbody>{canary_rows or '<tr><td colspan="5" style="text-align:center;color:#999;padding:20px;">暂无灰度记录</td></tr>'}</tbody>
                </table>
            </div>
        </div>""" if canary_summary else ""

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>审计明细 - {release_id}</title>
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
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; font-size: 13px; }}
        th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid #eee; }}
        th {{ background: #f8f9fa; font-weight: 600; color: #555; white-space: nowrap; }}
        .badge {{ display: inline-block; padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: 600; }}
        .badge-pass {{ background: #d5f5e3; color: #1e8449; }}
        .badge-fail {{ background: #fadbd8; color: #c0392b; }}
        .badge-warn {{ background: #fef9e7; color: #b7950b; }}
        .badge-info {{ background: #d6eaf8; color: #2471a3; }}
        .footer {{ text-align: center; padding: 20px; color: #7f8c8d; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>审计明细导出</h1>
            <div class="meta">
                发布单号: {release_id} | 版本: {record_data.get('version', '-')} |
                前版本: {record_data.get('previous_version', '-')} |
                类型: {'常规迭代' if record_data.get('release_type') == 'routine' else '紧急热修复'} |
                状态: {record_data.get('status', '-')} |
                导出时间: {datetime.now().isoformat()}
            </div>
        </div>
        {filters_html}
        <div class="section">
            <div class="section-title">审计完整性校验</div>
            <div class="section-body">
                <div style="font-size:16px;">完整性结果: {integrity_badge}</div>
                {issues_html}
            </div>
        </div>
        {approval_html}
        {canary_html}
        <div class="section">
            <div class="section-title">审计事件明细 (共 {len(entries)} 条)</div>
            <div class="section-body">
                <table>
                    <thead><tr><th>时间</th><th>分类</th><th>事件</th><th>action</th><th>操作人</th><th>详情</th><th>电子签名</th></tr></thead>
                    <tbody>{rows or '<tr><td colspan="7" style="text-align:center;color:#999;padding:20px;">暂无审计记录</td></tr>'}</tbody>
                </table>
            </div>
        </div>
        <div class="footer">本报表由医药冷链温湿度监控系统版本发布与智能回滚自动化平台自动生成 | 符合GSP合规审计要求</div>
    </div>
</body>
</html>"""


def _is_deadline_overdue(deadline_str: str) -> bool:
    if not deadline_str:
        return False
    try:
        from datetime import datetime as _dt
        dl = _dt.fromisoformat(deadline_str)
        return _dt.now() > dl
    except (ValueError, TypeError):
        return False


def _time_left_text(deadline_str: str) -> str:
    if not deadline_str:
        return "未设置超时"
    try:
        from datetime import datetime as _dt
        dl = _dt.fromisoformat(deadline_str)
        delta = dl - _dt.now()
        total_seconds = int(delta.total_seconds())
        if total_seconds < 0:
            overdue = abs(total_seconds)
            hours, rem = divmod(overdue, 3600)
            minutes, secs = divmod(rem, 60)
            return f"已超时 {hours}h{minutes:02d}m"
        hours, rem = divmod(total_seconds, 3600)
        minutes, secs = divmod(rem, 60)
        return f"剩余 {hours}h{minutes:02d}m{secs:02d}s (截止: {deadline_str})"
    except (ValueError, TypeError):
        return "未设置超时"


def _render_approval_record(r, indent="  ", show_group_label=None):
    role_display = ApprovalEngine.APPROVER_MAP.get(r.role, r.role)
    action_val = r.action.value
    status_icon = {"approve": "[PASS]", "reject": "[REJECT]", "pending": "[PENDING]"}.get(action_val, "[?]")

    lines = []
    prefix = f"{indent}{status_icon}"
    if show_group_label:
        lines.append(f"{prefix} {show_group_label} - {role_display}")
    else:
        lines.append(f"{prefix} 第{r.level}级 - {role_display}")

    sub_indent = indent + "   "
    lines.append(f"{sub_indent}级别: {r.level}  角色: {r.role}")

    if r.timeout_minutes or r.deadline:
        overdue = _is_deadline_overdue(r.deadline)
        time_text = _time_left_text(r.deadline)
        badge = "[OVERDUE]" if overdue else "[OK]"
        lines.append(f"{sub_indent}超时: {badge} 配置 {r.timeout_minutes}分钟 | {time_text}")

    if action_val != "pending":
        lines.append(f"{sub_indent}审批人: {r.approver}")
        lines.append(f"{sub_indent}时间: {r.timestamp or '-'}")
        if r.comment:
            lines.append(f"{sub_indent}意见: {r.comment}")
        if r.is_post_sign:
            lines.append(f"{sub_indent}[事后补签]")
    else:
        lines.append(f"{sub_indent}审批人: {r.approver} (待审批)")
        lines.append(f"{sub_indent}时间: 待处理")
    return "\n".join(lines)


def run_approvals(platform: ReleasePlatform, args: argparse.Namespace) -> dict:
    release_id = args.release_id
    record_data = platform.db.get_release_record(release_id)
    if not record_data:
        print(f"[ERROR] 发布单不存在: {release_id}")
        return {"success": False}

    flow = platform._load_approval_flow(release_id)
    if not flow:
        print(f"[WARN] 发布单尚未初始化审批流 (当前状态: {record_data['status']})")
        return {"success": False}

    release_type = flow.release_type.value
    is_hotfix = release_type == "hotfix"

    print(f"\n审批节点详情 [release_id={release_id}]")
    print(f"{'='*60}")
    print(f"  发布类型: {'紧急热修复' if is_hotfix else '常规迭代'}")
    print(f"  审批流状态: {'已完成' if flow.is_completed else '已拒绝' if flow.is_rejected else '进行中'}")

    if is_hotfix:
        if flow.hotfix_reason:
            print(f"  紧急原因: {flow.hotfix_reason}")
        if flow.deviation_report_id:
            print(f"  偏差报告: {flow.deviation_report_id}")

    print()

    if is_hotfix:
        level_groups = {}
        for record in flow.records:
            level_groups.setdefault(record.level, []).append(record)

        for lvl in sorted(level_groups.keys()):
            level_records = level_groups[lvl]
            if lvl == 1:
                print(f"  [并行审批] 第{lvl}级 - 质量与物流并行评审:")
            elif lvl == 2:
                print(f"  [最终确认] 第{lvl}级 - 质量负责人最终放行:")
            else:
                print(f"  第{lvl}级:")

            for r in level_records:
                print(_render_approval_record(r, indent="    "))
    else:
        for record in flow.records:
            print(_render_approval_record(record, indent="  "))

    pending_count = sum(1 for r in flow.records if r.action.value == "pending")
    approved_count = sum(1 for r in flow.records if r.action.value == "approve")
    rejected_count = sum(1 for r in flow.records if r.action.value == "reject")

    print(f"\n  汇总: 通过 {approved_count} / 待审批 {pending_count} / 拒绝 {rejected_count} (共 {len(flow.records)} 个节点)")

    if flow.is_rejected:
        rejects = [r for r in flow.records if r.action.value == "reject"]
        for rj in rejects:
            role_display = ApprovalEngine.APPROVER_MAP.get(rj.role, rj.role)
            print(f"  被拒详情: 第{rj.level}级 {role_display} - {rj.approver} - {rj.comment or '无意见'}")

    if not flow.is_completed and not flow.is_rejected:
        pending_roles = [ApprovalEngine.APPROVER_MAP.get(r.role, r.role) for r in flow.records if r.action.value == "pending"]
        if pending_roles:
            print(f"  卡在: {', '.join(pending_roles)}")
            next_r = next((r for r in flow.records if r.action.value == "pending"), None)
            if next_r:
                print(f"\n  下一步审批命令:")
                print(f"    python main.py approve --release-id {release_id} --level {next_r.level} --role {next_r.role} --action approve --approver '{ApprovalEngine.APPROVER_MAP.get(next_r.role, next_r.role)}'")
                print(f"\n  催办命令:")
                print(f"    python main.py remind --release-id {release_id}")

    print(f"{'='*60}\n")
    return {"success": True}


def run_releases(platform: ReleasePlatform, args: argparse.Namespace) -> dict:
    all_records = platform.db.list_release_records(limit=max(args.limit or 50, 50))
    if not all_records:
        print("\n[INFO] 暂无发布单记录。\n")
        return {"success": True}

    records = all_records
    if args.status:
        records = [r for r in records if r.get("status") == args.status]
    if args.type:
        records = [r for r in records if r.get("release_type") == args.type]
    if args.applicant:
        records = [r for r in records if r.get("applicant") and args.applicant.lower() in r["applicant"].lower()]

    records = sorted(records, key=lambda r: r.get("created_at", ""), reverse=True)
    limit = args.limit or 20
    records = records[:limit]

    print(f"\n发布单列表 (共 {len(records)} 条 / 总数 {len(all_records)} 条)")
    if args.status or args.type or args.applicant:
        filters = []
        if args.status: filters.append(f"状态={args.status}")
        if args.type: filters.append(f"类型={args.type}")
        if args.applicant: filters.append(f"申请人={args.applicant}")
        print(f"  筛选条件: {', '.join(filters)}")
    print(f"{'='*100}")
    header = f"  {'发布单号':<28} {'版本':<12} {'类型':<8} {'状态':<18} {'申请人':<8} {'最近事件':<20} 备注"
    print(header)
    print(f"  {'-'*96}")

    for r in records:
        rid = r["release_id"]
        status = r.get("status", "")
        rtype = r.get("release_type", "")
        version = r.get("version", "")
        applicant = r.get("applicant", "")
        created = r.get("created_at", "")

        last_event_text = ""
        blocker = ""

        audit_logs = platform.audit_engine.get_audit_trail(rid)
        if audit_logs:
            sorted_logs = sorted(audit_logs, key=lambda x: x.get("timestamp", ""))
            key_actions = [
                "approval_completed", "approval_reject",
                "canary_started", "canary_failed",
                "release_completed", "rollback_executed", "rollback_failed",
                "review_report_generated", "approval_approve",
            ]
            key_logs = [log for log in sorted_logs if log.get("action") in key_actions]
            if key_logs:
                last = key_logs[-1]
                last_event_text = last.get("timestamp", "")[:16].replace("T", " ")
                last_action = last.get("action", "")
                if last_action == "canary_failed":
                    detail = last.get("details", {}) or {}
                    reason = detail.get("reason", "灰度失败")
                    blocker = f"[FAIL] {reason}"

        pending_roles_text = ""
        if status == ReleaseStatus.PENDING_APPROVAL.value:
            flow = platform._load_approval_flow(rid)
            if flow:
                if flow.is_rejected:
                    rejects = [x for x in flow.records if x.action.value == "reject"]
                    if rejects:
                        rj = rejects[0]
                        role_display = ApprovalEngine.APPROVER_MAP.get(rj.role, rj.role)
                        blocker = f"[REJECT] L{rj.level} {role_display} ({rj.comment or '无意见'})"
                elif not flow.is_completed:
                    pending = [ApprovalEngine.APPROVER_MAP.get(x.role, x.role) for x in flow.records if x.action.value == "pending"]
                    pending_roles_text = "/".join(pending)

        if status == ReleaseStatus.CANARY_FAILED.value:
            if not blocker:
                blocker = "[FAIL] 灰度失败"
        elif status == ReleaseStatus.ROLLED_BACK.value:
            blocker = "[ROLLBACK] 已回滚"
        elif status == ReleaseStatus.APPROVAL_REJECTED.value:
            flow = platform._load_approval_flow(rid)
            if flow:
                rejects = [x for x in flow.records if x.action.value == "reject"]
                if rejects:
                    rj = rejects[0]
                    role_display = ApprovalEngine.APPROVER_MAP.get(rj.role, rj.role)
                    blocker = f"[REJECT] L{rj.level} {role_display} ({rj.comment or '无意见'})"

        type_short = "常规" if rtype == "routine" else "热修"
        pend_text = f"待:{pending_roles_text}" if pending_roles_text else ""
        remark_parts = [p for p in [pend_text, blocker] if p]
        remark = "  ".join(remark_parts)

        line = f"  {rid:<28} {version:<12} {type_short:<6} {status:<20} {applicant:<8} {last_event_text:<20} {remark}"
        print(line)

    print(f"{'='*100}\n")
    print("  快速操作:")
    if records:
        first = records[0]["release_id"]
        print(f"    查看详情: python main.py status --release-id {first}")
        print(f"    审批节点: python main.py approvals --release-id {first}")
    print()
    return {"success": True}


def run_remind(platform: ReleasePlatform, args: argparse.Namespace) -> dict:
    release_id = args.release_id
    record_data = platform.db.get_release_record(release_id)
    if not record_data:
        print(f"[ERROR] 发布单不存在: {release_id}")
        return {"success": False}

    flow = platform._load_approval_flow(release_id)
    if not flow:
        print(f"[WARN] 发布单尚未初始化审批流。")
        return {"success": False}

    if flow.is_completed:
        print("[INFO] 审批流已全部完成，无需催办。")
        return {"success": True}
    if flow.is_rejected:
        print("[WARN] 审批流已被拒绝，无法催办。")
        return {"success": False}

    pending_records = [r for r in flow.records if r.action.value == "pending"]
    if not pending_records:
        print("[INFO] 当前无待审批节点。")
        return {"success": True}

    release_type = flow.release_type.value
    is_hotfix = release_type == "hotfix"

    exec_type = "parallel" if is_hotfix else "serial"

    target_records = pending_records
    if exec_type == "serial":
        levels_pending = sorted({r.level for r in pending_records})
        min_level = min(levels_pending)
        target_records = [r for r in pending_records if r.level == min_level]

    print(f"\n审批催办 [release_id={release_id}]")
    print(f"{'='*60}")
    print(f"  发布类型: {'紧急热修复' if is_hotfix else '常规迭代'}")
    print(f"  催办节点数: {len(target_records)}")
    print()

    reminded = []
    for r in target_records:
        role_display = ApprovalEngine.APPROVER_MAP.get(r.role, r.role)
        overdue = _is_deadline_overdue(r.deadline)
        overdue_tag = "[已超时]" if overdue else "[未超时]"
        print(f"  - 第{r.level}级 {role_display} {overdue_tag}")
        if r.deadline:
            print(f"    截止时间: {r.deadline} ({_time_left_text(r.deadline)})")
        reminded.append({
            "level": r.level,
            "role": r.role,
            "role_display": role_display,
            "approver": r.approver,
            "overdue": overdue,
            "deadline": r.deadline,
        })

    operator = args.operator or "system"
    details = {
        "reminded_count": len(reminded),
        "reminded_targets": reminded,
        "operator": operator,
    }
    if args.reason:
        details["reason"] = args.reason

    platform.audit_engine.log_action(
        release_id=release_id,
        action="reminder_sent",
        actor=operator,
        details=details,
        electronic_signature=f"SIG-REMIND-{uuid.uuid4().hex[:12]}",
    )

    print()
    print(f"  催办记录已写入审计日志 [DONE]")
    if args.reason:
        print(f"  催办原因: {args.reason}")
    print(f"{'='*60}\n")
    return {"success": True, "reminded": reminded}


def run_deploy(platform: ReleasePlatform, args: argparse.Namespace) -> dict:
    release_id = args.release_id
    record_data = platform.db.get_release_record(release_id)
    if not record_data:
        print(f"[ERROR] 发布单不存在: {release_id}")
        return {"success": False}

    current_status = record_data["status"]
    flow = platform._load_approval_flow(release_id)

    if current_status in [ReleaseStatus.APPROVAL_REJECTED.value]:
        if flow:
            rejects = [r for r in flow.records if r.action.value == "reject"]
            print(f"[ERROR] 发布单审批被拒绝，无法执行发布")
            for rj in rejects:
                role_display = ApprovalEngine.APPROVER_MAP.get(rj.role, rj.role)
                print(f"  拒绝级别: 第{rj.level}级")
                print(f"  拒绝角色: {role_display} ({rj.role})")
                print(f"  拒绝人: {rj.approver}")
                print(f"  拒绝时间: {rj.timestamp or '-'}")
                print(f"  拒绝意见: {rj.comment or '（无意见）'}")
        else:
            print(f"[ERROR] 发布单审批被拒绝，无法执行发布。")
        return {"success": False}

    if current_status in [ReleaseStatus.CANARY_DEPLOYING.value, ReleaseStatus.FULLY_RELEASED.value,
                          ReleaseStatus.ROLLED_BACK.value]:
        if current_status == ReleaseStatus.CANARY_DEPLOYING.value:
            print(f"[WARN] 发布单正在灰度发布中，请等待...")
        elif current_status == ReleaseStatus.FULLY_RELEASED.value:
            print(f"[INFO] 发布单已全量发布完成，无需重复操作。")
            return {"success": True}
        elif current_status == ReleaseStatus.ROLLED_BACK.value:
            print(f"[ERROR] 发布单已回滚，无法继续发布。请创建新版本发布单。")
            return {"success": False}

    if current_status != ReleaseStatus.APPROVAL_PASSED.value:
        if current_status == ReleaseStatus.PENDING_APPROVAL.value:
            if flow:
                pending_roles = [ApprovalEngine.APPROVER_MAP.get(r.role, r.role)
                                 for r in flow.records if r.action.value == "pending"]
                rejected_roles = [ApprovalEngine.APPROVER_MAP.get(r.role, r.role)
                                  for r in flow.records if r.action.value == "reject"]
                print(f"[ERROR] 发布单尚未完成审批 (当前状态: {current_status})")
                if pending_roles:
                    print(f"  待审批: {', '.join(pending_roles)}")
                if rejected_roles:
                    print(f"  已拒绝: {', '.join(rejected_roles)}")
                next_r = next((r for r in flow.records if r.action.value == "pending"), None)
                if next_r:
                    print(f"  下一步: python main.py approve --release-id {release_id} --level {next_r.level} --role {next_r.role} --action approve --approver '{ApprovalEngine.APPROVER_MAP.get(next_r.role, next_r.role)}'")
            else:
                print(f"[ERROR] 发布单尚未完成审批 (当前状态: {current_status})")
                print("  请先通过 approve 命令完成所有审批后再执行灰度发布。")
        else:
            print(f"[ERROR] 发布单状态不允许启动灰度发布 (当前状态: {current_status})")
        return {"success": False}

    print(f"\n{'='*60}")
    print(f"  发布摘要 [release_id={release_id}]")
    print(f"{'='*60}")
    print(f"  版本: {record_data['previous_version']} -> {record_data['version']}")
    print(f"  类型: {'常规迭代' if record_data['release_type'] == 'routine' else '紧急热修复'}")

    pre_check_data = record_data.get("pre_check_report")
    if pre_check_data:
        try:
            pcr = json.loads(pre_check_data)
            passed_count = sum(1 for r in pcr.get("results", []) if r["status"] == "pass")
            failed_count = sum(1 for r in pcr.get("results", []) if r["status"] == "fail")
            print(f"  前置校验: 通过 {passed_count}/{passed_count + failed_count} 项")
        except (json.JSONDecodeError, KeyError):
            print(f"  前置校验: 已通过")
    else:
        print(f"  前置校验: 已通过")

    if flow:
        approved_count = sum(1 for r in flow.records if r.action.value == "approve")
        total_count = len(flow.records)
        print(f"  审批完成: {approved_count}/{total_count} 个节点已通过")

    canary_stages = platform.canary_engine.create_canary_stages()
    stage_names = [s.name for s in canary_stages]
    print(f"  灰度计划: {len(canary_stages)} 阶段")
    for i, stage in enumerate(canary_stages):
        print(f"    {i+1}. {stage.name} ({stage.weight_percent}%)")
    print(f"{'='*60}")

    print(f"\n[1/2] 执行线路灰度发布 [release_id={release_id}]...")
    canary_result = platform.start_canary_release(release_id)
    final_status = canary_result.get("final_status", "unknown")

    if canary_result.get("success"):
        print(f"  灰度发布全量完成 [PASS]")
        print(f"  最终状态: {final_status}")
    else:
        print(f"  灰度发布失败 [FAIL]")
        print(f"  最终状态: {final_status}")
        if canary_result.get("rollback_performed"):
            print(f"  已执行智能回滚 [ROLLBACK]")

    print(f"\n[2/2] 生成复盘报表...")
    print(f"  复盘报表已生成 [DONE]")

    print(f"\n{'='*60}")
    print(f"  发布流程结束")
    print(f"  发布单号: {release_id}")
    print(f"  最终状态: {final_status}")
    print(f"{'='*60}\n")

    return canary_result


def run_pre_check_only(platform: ReleasePlatform, args: argparse.Namespace) -> dict:
    record = platform.create_release(
        version=args.version,
        previous_version=args.previous_version or "unknown",
        release_type=args.type,
        applicant=args.applicant,
        description=args.description or "前置校验测试",
    )

    print(f"\n执行发布前置校验 [release_id={record.release_id}]...\n")
    result = platform.run_pre_check(record.release_id)

    print(f"前置校验结果: {'全部通过 [PASS]' if result['success'] else '存在未通过项 [FAIL]'}\n")
    for r in result.get("results", []):
        icon = {"pass": "[PASS]", "fail": "[FAIL]", "warning": "[WARN]", "skipped": "[SKIP]"}.get(r["status"], "[?]")
        print(f"  {icon} {r['check_name']}")
        print(f"     得分: {r['score']:.4f} | 阈值: {r['threshold']:.4f}")
        print(f"     {r['message']}")
        if r.get("remediation"):
            print(f"     修复建议: {r['remediation']}")
        print()

    return result


def run_approval_only(platform: ReleasePlatform, args: argparse.Namespace) -> dict:
    record_data = platform.db.get_release_record(args.release_id)
    if not record_data:
        print(f"[ERROR] 发布单不存在: {args.release_id}")
        return {"success": False}

    if not args.action or not args.role:
        print("[ERROR] 审批操作需要指定 --action (approve/reject) 和 --role (quality/logistics/quality_head)")
        return {"success": False}

    if not args.approver:
        print("[ERROR] 请指定审批人 --approver")
        return {"success": False}

    release_type = record_data["release_type"]
    role_display = ApprovalEngine.APPROVER_MAP.get(args.role, args.role)

    print(f"\n执行审批操作 [release_id={args.release_id}]")
    print(f"  发布类型: {'常规迭代' if release_type == 'routine' else '紧急热修复'}")
    print(f"  审批级别: 第{args.level}级")
    print(f"  审批角色: {role_display}")
    print(f"  审批操作: {'通过' if args.action == 'approve' else '拒绝'}")
    print(f"  审批人: {args.approver}")
    if args.comment:
        print(f"  审批意见: {args.comment}")
    if args.post_sign:
        print(f"  [WARN] 本次为事后补签")
    print()

    result = platform.process_approval(
        release_id=args.release_id,
        level=args.level,
        role=args.role,
        action=args.action,
        approver=args.approver,
        comment=args.comment,
        is_post_sign=args.post_sign or False,
    )

    if not result["success"]:
        print(f"[ERROR] 审批失败: {result.get('message', '未知错误')}")
        print()
        return result

    action_display = "通过 [PASS]" if args.action == "approve" else "拒绝 [REJECT]"
    print(f"第{args.level}级 - {role_display} 审批{action_display}\n")

    approval_result = result.get("result", {})
    if approval_result.get("flow_rejected"):
        print(f"[INFO] 审批流已被拒绝，发布流程终止。")
    elif approval_result.get("flow_completed"):
        print(f"[INFO] 所有审批已全部通过 [PASS]")
        print(f"  下一步: 启动灰度发布")
        print(f"     python main.py deploy --release-id {args.release_id}")
    else:
        pending = approval_result.get("pending_roles")
        if pending:
            print(f"[INFO] 仍有待审批角色: {pending}")
        else:
            next_role = approval_result.get("next_role")
            next_level = approval_result.get("next_level")
            if next_role and next_level:
                next_display = ApprovalEngine.APPROVER_MAP.get(next_role, next_role)
                print(f"[INFO] 下一步: 第{next_level}级审批")
                print(f"     python main.py approve --release-id {args.release_id} --level {next_level} --role {next_role} --action approve --approver '{next_display}'")

    print()
    return result


def run_status(platform: ReleasePlatform, args: argparse.Namespace) -> dict:
    result = platform.get_release_status(args.release_id)
    if not result["success"]:
        print(f"发布单不存在: {args.release_id}")
        return result

    record = result["release"]
    print(f"\n发布单状态 [release_id={args.release_id}]")
    print(f"{'='*50}")
    print(f"  版本: {record['version']}")
    print(f"  前版本: {record['previous_version']}")
    print(f"  类型: {'常规迭代' if record['release_type'] == 'routine' else '紧急热修复'}")
    print(f"  状态: {record['status']}")
    print(f"  申请人: {record['applicant']}")
    print(f"  创建时间: {record['created_at']}")
    print(f"  更新时间: {record['updated_at']}")
    print(f"  审计日志数: {result['audit_log_count']}")
    integrity = result["audit_integrity"]
    print(f"  审计完整性: {'通过 [PASS]' if integrity['integrity_valid'] else '未通过 [FAIL]'}")
    if not integrity["integrity_valid"] and integrity.get("issues"):
        for issue in integrity["issues"]:
            print(f"    - {issue}")

    audit_logs = platform.audit_engine.get_audit_trail(args.release_id)
    if audit_logs:
        sorted_logs = sorted(audit_logs, key=lambda x: x.get("timestamp", ""))
        key_actions = [
            "approval_completed", "approval_reject",
            "canary_started", "canary_failed",
            "release_completed", "rollback_executed", "rollback_failed",
            "review_report_generated",
            "approval_approve", "reminder_sent", "audit_exported",
        ]
        key_logs = [log for log in sorted_logs if log.get("action") in key_actions]
        if key_logs:
            print(f"\n  关键审计事件:")
            for log in key_logs[-8:]:
                action = log.get("action", "")
                display = ACTION_DISPLAY.get(action, action)
                ts = log.get("timestamp", "-")
                actor = log.get("actor", "-")
                details = log.get("details", {}) or {}
                extra = ""
                if action == "approval_approve" and details:
                    lvl = details.get("level", "")
                    role_d = details.get("role", "")
                    if lvl:
                        extra = f" (L{lvl}-{ApprovalEngine.APPROVER_MAP.get(role_d, role_d)})"
                elif action == "reminder_sent":
                    n = details.get("reminded_count", "")
                    if n:
                        extra = f" ({n}人)"
                elif action == "audit_exported":
                    fmt = details.get("format", "")
                    if fmt:
                        extra = f" ({fmt.upper()})"
                print(f"    {ts}  {display}{extra}  ({actor})")

    print(f"{'='*50}\n")

    return result


def main():
    parser = argparse.ArgumentParser(
        description="医药冷链温湿度监控系统 - 版本发布与智能回滚自动化平台"
    )
    parser.add_argument("--config", default="config/settings.yaml", help="配置文件路径")
    subparsers = parser.add_subparsers(dest="command", help="可用命令")

    release_parser = subparsers.add_parser("release", help="执行完整发布流程")
    release_parser.add_argument("--version", required=True, help="目标版本号")
    release_parser.add_argument("--previous-version", required=True, help="当前版本号")
    release_parser.add_argument("--type", choices=["routine", "hotfix"], default="routine", help="发布类型")
    release_parser.add_argument("--applicant", required=True, help="申请人")
    release_parser.add_argument("--description", default="", help="发布描述")
    release_parser.add_argument("--hotfix-reason", default="", help="热修复原因(hotfix必填)")
    release_parser.add_argument("--deviation-report", default="", help="偏差报告编号(hotfix必填)")

    check_parser = subparsers.add_parser("check", help="仅执行前置校验")
    check_parser.add_argument("--version", required=True, help="目标版本号")
    check_parser.add_argument("--previous-version", default="", help="当前版本号")
    check_parser.add_argument("--type", choices=["routine", "hotfix"], default="routine")
    check_parser.add_argument("--applicant", default="test_user", help="申请人")
    check_parser.add_argument("--description", default="", help="描述")

    approve_parser = subparsers.add_parser("approve", help="审批操作")
    approve_parser.add_argument("--release-id", required=True, help="发布单号")
    approve_parser.add_argument("--level", type=int, default=1, help="审批级别")
    approve_parser.add_argument("--role", required=True, choices=["quality", "logistics", "quality_head"])
    approve_parser.add_argument("--action", required=True, choices=["approve", "reject"])
    approve_parser.add_argument("--approver", default="", help="审批人")
    approve_parser.add_argument("--comment", default="", help="审批意见")
    approve_parser.add_argument("--post-sign", action="store_true", help="事后补签")

    status_parser = subparsers.add_parser("status", help="查询发布状态")
    status_parser.add_argument("--release-id", required=True, help="发布单号")

    approvals_parser = subparsers.add_parser("approvals", help="查看审批节点详情")
    approvals_parser.add_argument("--release-id", required=True, help="发布单号")

    releases_parser = subparsers.add_parser("releases", help="发布单列表")
    releases_parser.add_argument("--status", default="", help="按状态筛选 (pending_approval/approval_passed/fully_released 等)")
    releases_parser.add_argument("--type", choices=["routine", "hotfix"], default="", help="按发布类型筛选")
    releases_parser.add_argument("--applicant", default="", help="按申请人筛选")
    releases_parser.add_argument("--limit", type=int, default=20, help="显示条数上限 (默认20)")

    remind_parser = subparsers.add_parser("remind", help="对当前待审批角色生成催办记录")
    remind_parser.add_argument("--release-id", required=True, help="发布单号")
    remind_parser.add_argument("--operator", default="system", help="操作人/催办人")
    remind_parser.add_argument("--reason", default="", help="催办原因")

    deploy_parser = subparsers.add_parser("deploy", help="审批通过后执行灰度发布")
    deploy_parser.add_argument("--release-id", required=True, help="发布单号")

    audit_parser = subparsers.add_parser("audit", help="导出审计明细")
    audit_parser.add_argument("--release-id", required=True, help="发布单号")
    audit_parser.add_argument("--format", choices=["json", "html"], default="json", help="导出格式")
    audit_parser.add_argument("--action", default="", help="按事件类型过滤 (逗号分隔多个action)")
    audit_parser.add_argument("--since", default="", help="起始时间 (ISO8601, 如 2026-06-21T00:00:00)")
    audit_parser.add_argument("--until", default="", help="截止时间 (ISO8601)")
    audit_parser.add_argument("--operator", default="system", help="操作人/导出人")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    platform = ReleasePlatform(config_path=args.config)

    if args.command == "release":
        run_full_release(platform, args)
    elif args.command == "check":
        run_pre_check_only(platform, args)
    elif args.command == "approve":
        run_approval_only(platform, args)
    elif args.command == "approvals":
        run_approvals(platform, args)
    elif args.command == "releases":
        run_releases(platform, args)
    elif args.command == "remind":
        run_remind(platform, args)
    elif args.command == "status":
        run_status(platform, args)
    elif args.command == "deploy":
        run_deploy(platform, args)
    elif args.command == "audit":
        run_audit_export(platform, args)


if __name__ == "__main__":
    main()
