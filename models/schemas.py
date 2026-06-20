from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Any


class ReleaseType(Enum):
    ROUTINE = "routine"
    HOTFIX = "hotfix"


class ReleaseStatus(Enum):
    PENDING_CHECK = "pending_check"
    CHECK_FAILED = "check_failed"
    CHECK_PASSED = "check_passed"
    PENDING_APPROVAL = "pending_approval"
    APPROVAL_REJECTED = "approval_rejected"
    APPROVAL_PASSED = "approval_passed"
    CANARY_DEPLOYING = "canary_deploying"
    CANARY_STAGE_PASSED = "canary_stage_passed"
    CANARY_FAILED = "canary_failed"
    ROLLING_BACK = "rolling_back"
    ROLLED_BACK = "rolled_back"
    FULLY_RELEASED = "fully_released"
    CIRCUIT_BREAKER_OPEN = "circuit_breaker_open"


class ApprovalAction(Enum):
    APPROVE = "approve"
    REJECT = "reject"
    PENDING = "pending"


class CheckResultStatus(Enum):
    PASS = "pass"
    FAIL = "fail"
    WARNING = "warning"
    SKIPPED = "skipped"


class CircuitBreakerState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass
class CheckResult:
    check_name: str
    status: CheckResultStatus
    score: float
    threshold: float
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class PreCheckReport:
    release_id: str
    results: List[CheckResult] = field(default_factory=list)
    overall_passed: bool = False
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def add_result(self, result: CheckResult):
        self.results.append(result)
        self._evaluate()

    def _evaluate(self):
        critical_checks = [r for r in self.results if r.status == CheckResultStatus.FAIL]
        self.overall_passed = len(critical_checks) == 0


@dataclass
class ApprovalRecord:
    level: int
    role: str
    approver: str
    action: ApprovalAction = ApprovalAction.PENDING
    comment: str = ""
    timestamp: Optional[str] = None
    is_post_sign: bool = False


@dataclass
class ApprovalFlow:
    release_id: str
    release_type: ReleaseType
    records: List[ApprovalRecord] = field(default_factory=list)
    current_level: int = 1
    is_completed: bool = False
    is_rejected: bool = False
    hotfix_reason: str = ""
    deviation_report_id: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class CanaryStage:
    name: str
    weight_percent: float
    duration_minutes: int
    routes: Any
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    status: str = "pending"
    metrics: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CircuitBreaker:
    state: CircuitBreakerState = CircuitBreakerState.CLOSED
    failure_count: int = 0
    success_count: int = 0
    last_failure_time: Optional[str] = None
    last_state_change: Optional[str] = None
    half_open_retries: int = 0


@dataclass
class RollbackSnapshot:
    version: str
    config_snapshot: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    checksum: str = ""


@dataclass
class ReleaseRecord:
    release_id: str
    version: str
    previous_version: str
    release_type: ReleaseType
    status: ReleaseStatus = ReleaseStatus.PENDING_CHECK
    applicant: str = ""
    description: str = ""
    pre_check_report: Optional[PreCheckReport] = None
    approval_flow: Optional[ApprovalFlow] = None
    canary_stages: List[CanaryStage] = field(default_factory=list)
    circuit_breaker: CircuitBreaker = field(default_factory=CircuitBreaker)
    rollback_snapshot: Optional[RollbackSnapshot] = None
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    completed_at: Optional[str] = None
    audit_trail: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class AuditLogEntry:
    release_id: str
    action: str
    actor: str
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    electronic_signature: str = ""


@dataclass
class ReviewReport:
    release_id: str
    version: str
    release_type: ReleaseType
    pre_check_summary: Dict[str, Any] = field(default_factory=dict)
    approval_summary: Dict[str, Any] = field(default_factory=dict)
    canary_summary: Dict[str, Any] = field(default_factory=dict)
    rollback_summary: Optional[Dict[str, Any]] = None
    compliance_notes: List[str] = field(default_factory=list)
    generated_at: str = field(default_factory=lambda: datetime.now().isoformat())
