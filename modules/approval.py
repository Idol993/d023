import logging
from datetime import datetime
from typing import Dict, Any, List, Optional

from models.schemas import (
    ReleaseType,
    ApprovalAction,
    ApprovalRecord,
    ApprovalFlow,
)


class ApprovalEngine:
    ROUTINE_FLOW = "routine"
    HOTFIX_FLOW = "hotfix"

    APPROVER_MAP = {
        "quality": "质量团队-GSP合规与数据完整性评估",
        "logistics": "物流团队-运输线路与仓储业务影响评估",
        "quality_head": "质量负责人-最终放行与合规责任确认",
    }

    def __init__(self, config: dict):
        self.channels = config.get("channels", {})
        self.logger = logging.getLogger("approval.engine")

    def create_flow(
        self,
        release_id: str,
        release_type: ReleaseType,
        hotfix_reason: str = "",
        deviation_report_id: str = "",
    ) -> ApprovalFlow:
        flow_type = self.ROUTINE_FLOW if release_type == ReleaseType.ROUTINE else self.HOTFIX_FLOW
        channel = self.channels.get(flow_type, {})

        if not channel:
            raise ValueError(f"未找到发布通道配置: {flow_type}")

        flow = ApprovalFlow(
            release_id=release_id,
            release_type=release_type,
            hotfix_reason=hotfix_reason,
            deviation_report_id=deviation_report_id,
        )

        if flow_type == self.HOTFIX_FLOW:
            if not hotfix_reason:
                raise ValueError("紧急热修复发布必须提供紧急原因")
            self.logger.warning(
                f"紧急热修复发布 [release_id={release_id}], 原因: {hotfix_reason}"
            )

        flow.records = self._init_approval_records(channel)
        self.logger.info(
            f"审批流已创建 [release_id={release_id}], 通道={channel.get('name')}, "
            f"类型={channel.get('type')}, 级数={len(set(r.level for r in flow.records))}"
        )
        return flow

    def _init_approval_records(self, channel: dict) -> List[ApprovalRecord]:
        records = []
        levels = channel.get("levels", [])
        flow_type = channel.get("type", "serial")

        for level_conf in levels:
            record = ApprovalRecord(
                level=level_conf["level"],
                role=level_conf["role"],
                approver=self.APPROVER_MAP.get(level_conf["role"], level_conf["role"]),
            )
            records.append(record)

        if flow_type == "serial":
            for i, record in enumerate(records):
                if record.level > 1:
                    pass

        return records

    def process_approval(
        self,
        flow: ApprovalFlow,
        level: int,
        role: str,
        action: ApprovalAction,
        approver: str,
        comment: str = "",
        is_post_sign: bool = False,
    ) -> Dict[str, Any]:
        channel_key = self.ROUTINE_FLOW if flow.release_type == ReleaseType.ROUTINE else self.HOTFIX_FLOW
        execution_type = self._get_flow_type(flow.release_type)

        if flow.is_completed:
            return {"success": False, "message": "审批流已完成，无法再操作"}

        if flow.is_rejected:
            return {"success": False, "message": "审批流已被拒绝，无法再操作"}

        target_record = None
        for record in flow.records:
            if record.level == level and record.role == role and record.action == ApprovalAction.PENDING:
                target_record = record
                break

        if not target_record:
            return {"success": False, "message": f"未找到待审批记录: level={level}, role={role}"}

        serial_validation = self._validate_serial_flow(flow, level, execution_type)
        if not serial_validation["valid"]:
            return {"success": False, "message": serial_validation["message"]}

        if channel_key == self.HOTFIX_FLOW and is_post_sign:
            if not flow.hotfix_reason:
                return {"success": False, "message": "事后补签必须关联紧急原因"}

        target_record.action = action
        target_record.comment = comment
        target_record.timestamp = datetime.now().isoformat()
        target_record.is_post_sign = is_post_sign

        self.logger.info(
            f"审批操作 [release_id={flow.release_id}]: level={level}, role={role}, "
            f"action={action.value}, approver={approver}"
            + (", 事后补签" if is_post_sign else "")
        )

        if action == ApprovalAction.REJECT:
            flow.is_rejected = True
            return {
                "success": True,
                "message": f"{role}审批已拒绝",
                "flow_completed": False,
                "flow_rejected": True,
            }

        return self._evaluate_flow_completion(flow, execution_type)

    def _validate_serial_flow(self, flow: ApprovalFlow, current_level: int, flow_type: str) -> dict:
        if flow_type != "serial":
            return {"valid": True}

        for record in flow.records:
            if record.level < current_level and record.action == ApprovalAction.PENDING:
                return {
                    "valid": False,
                    "message": f"串行审批: 第{record.level}级({record.role})尚未完成审批",
                }
            if record.level < current_level and record.action == ApprovalAction.REJECT:
                return {
                    "valid": False,
                    "message": f"串行审批: 第{record.level}级({record.role})已拒绝",
                }

        return {"valid": True}

    def _evaluate_flow_completion(self, flow: ApprovalFlow, flow_type: str) -> Dict[str, Any]:
        if flow_type == "serial":
            pending = [r for r in flow.records if r.action == ApprovalAction.PENDING]
            if not pending:
                flow.is_completed = True
                return {
                    "success": True,
                    "message": "串行审批全部通过",
                    "flow_completed": True,
                    "flow_rejected": False,
                }
            next_record = pending[0]
            flow.current_level = next_record.level
            return {
                "success": True,
                "message": f"当前级别审批通过，待下一级审批: {next_record.role}",
                "flow_completed": False,
                "flow_rejected": False,
                "next_level": next_record.level,
                "next_role": next_record.role,
            }

        elif flow_type == "parallel":
            level_groups = {}
            for record in flow.records:
                level_groups.setdefault(record.level, []).append(record)

            for lvl in sorted(level_groups.keys()):
                level_records = level_groups[lvl]
                all_done = all(r.action != ApprovalAction.PENDING for r in level_records)
                any_rejected = any(r.action == ApprovalAction.REJECT for r in level_records)

                if any_rejected:
                    flow.is_rejected = True
                    return {
                        "success": True,
                        "message": f"第{lvl}级并行审批存在拒绝",
                        "flow_completed": False,
                        "flow_rejected": True,
                    }

                if not all_done:
                    pending_roles = [r.role for r in level_records if r.action == ApprovalAction.PENDING]
                    return {
                        "success": True,
                        "message": f"第{lvl}级并行审批进行中，待审批: {pending_roles}",
                        "flow_completed": False,
                        "flow_rejected": False,
                        "pending_roles": pending_roles,
                    }

            flow.is_completed = True
            return {
                "success": True,
                "message": "并行审批全部通过",
                "flow_completed": True,
                "flow_rejected": False,
            }

        return {"success": False, "message": f"未知审批流类型: {flow_type}"}

    def get_flow_status(self, flow: ApprovalFlow) -> Dict[str, Any]:
        status = {
            "release_id": flow.release_id,
            "release_type": flow.release_type.value,
            "is_completed": flow.is_completed,
            "is_rejected": flow.is_rejected,
            "current_level": flow.current_level,
            "records": [],
        }

        for record in flow.records:
            status["records"].append({
                "level": record.level,
                "role": record.role,
                "approver": record.approver,
                "action": record.action.value,
                "comment": record.comment,
                "timestamp": record.timestamp,
                "is_post_sign": record.is_post_sign,
            })

        if flow.release_type == ReleaseType.HOTFIX:
            status["hotfix_reason"] = flow.hotfix_reason
            status["deviation_report_id"] = flow.deviation_report_id

        return status

    def check_post_sign_compliance(self, flow: ApprovalFlow) -> Dict[str, Any]:
        if flow.release_type != ReleaseType.HOTFIX:
            return {"compliant": True, "message": "非热修复发布，无需事后补签合规检查"}

        post_signed = [r for r in flow.records if r.is_post_sign]
        unsigned = [r for r in flow.records if r.action == ApprovalAction.PENDING and not r.is_post_sign]

        compliance_issues = []
        if unsigned:
            roles = [r.role for r in unsigned]
            compliance_issues.append(f"存在未补签审批: {roles}")

        for ps in post_signed:
            if not ps.timestamp:
                compliance_issues.append(f"事后补签缺少时间记录: {ps.role}")

        return {
            "compliant": len(compliance_issues) == 0,
            "message": "事后补签合规" if not compliance_issues else "; ".join(compliance_issues),
            "post_signed_count": len(post_signed),
            "unsigned_count": len(unsigned),
            "issues": compliance_issues,
        }

    def _get_flow_type(self, release_type: ReleaseType) -> str:
        channel_key = self.ROUTINE_FLOW if release_type == ReleaseType.ROUTINE else self.HOTFIX_FLOW
        channel = self.channels.get(channel_key, {})
        return channel.get("type", "serial")
