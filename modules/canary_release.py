import hashlib
import json
import random
import time
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional

from models.schemas import (
    CanaryStage,
    CircuitBreaker,
    CircuitBreakerState,
    RollbackSnapshot,
)


class CanaryReleaseEngine:
    def __init__(self, config: dict):
        self.enabled = config.get("enabled", True)
        self.stages_config = config.get("stages", [])
        self.cb_config = config.get("circuit_breaker", {})
        self.rollback_config = config.get("rollback", {})
        self.logger = logging.getLogger("canary.engine")
        self._metrics_buffer: List[Dict[str, Any]] = []

    def create_canary_stages(self) -> List[CanaryStage]:
        stages = []
        for stage_conf in self.stages_config:
            stage = CanaryStage(
                name=stage_conf["name"],
                weight_percent=stage_conf["weight_percent"],
                duration_minutes=stage_conf["duration_minutes"],
                routes=stage_conf["routes"],
            )
            stages.append(stage)
        return stages

    def create_rollback_snapshot(self, version: str, release_id: str, config_data: Dict[str, Any]) -> RollbackSnapshot:
        config_str = json.dumps(config_data, sort_keys=True, ensure_ascii=False)
        checksum = hashlib.sha256(config_str.encode("utf-8")).hexdigest()

        snapshot = RollbackSnapshot(
            version=version,
            config_snapshot=config_data,
            checksum=checksum,
        )

        self.logger.info(
            f"回滚快照已创建 [version={version}, release_id={release_id}, checksum={checksum[:16]}...]"
        )
        return snapshot

    def execute_canary_stage(
        self,
        stage: CanaryStage,
        circuit_breaker: CircuitBreaker,
        release_id: str,
    ) -> Dict[str, Any]:
        if not self.enabled:
            return {"success": True, "message": "灰度发布已禁用，直接全量", "stage_skipped": True}

        self.logger.info(
            f"执行灰度阶段 [{stage.name}] - 流量比例: {stage.weight_percent}%, "
            f"线路: {stage.routes}, 持续: {stage.duration_minutes}分钟"
        )

        stage.started_at = datetime.now().isoformat()
        stage.status = "running"

        check_interval = self.cb_config.get("check_interval_seconds", 10)
        min_samples = self.cb_config.get("min_sample_size", 100)
        error_threshold = self.cb_config.get("error_rate_threshold", 0.05)
        latency_threshold = self.cb_config.get("latency_threshold_ms", 2000)

        simulation_ticks = max(3, min(10, stage.duration_minutes))
        accumulated_metrics: Dict[str, Any] = {
            "total_requests": 0,
            "error_count": 0,
            "total_latency_ms": 0,
            "max_latency_ms": 0,
            "temp_anomalies": 0,
        }

        for tick in range(simulation_ticks):
            time.sleep(0.1)

            tick_metrics = self._simulate_traffic(stage.weight_percent)
            accumulated_metrics["total_requests"] += tick_metrics["requests"]
            accumulated_metrics["error_count"] += tick_metrics["errors"]
            accumulated_metrics["total_latency_ms"] += tick_metrics["total_latency"]
            accumulated_metrics["max_latency_ms"] = max(
                accumulated_metrics["max_latency_ms"], tick_metrics["max_latency"]
            )
            accumulated_metrics["temp_anomalies"] += tick_metrics["temp_anomalies"]

            self._metrics_buffer.append({
                "release_id": release_id,
                "stage": stage.name,
                "tick": tick,
                **tick_metrics,
            })

            if accumulated_metrics["total_requests"] >= min_samples:
                current_error_rate = accumulated_metrics["error_count"] / accumulated_metrics["total_requests"]
                current_avg_latency = accumulated_metrics["total_latency_ms"] / accumulated_metrics["total_requests"]

                cb_result = self._evaluate_circuit_breaker(
                    circuit_breaker,
                    current_error_rate,
                    current_avg_latency,
                    error_threshold,
                    latency_threshold,
                    release_id,
                )

                if cb_result["tripped"]:
                    stage.status = "failed"
                    stage.completed_at = datetime.now().isoformat()
                    stage.metrics = accumulated_metrics
                    self.logger.error(
                        f"灰度阶段 [{stage.name}] 熔断触发: {cb_result['reason']}"
                    )
                    return {
                        "success": False,
                        "message": f"熔断触发: {cb_result['reason']}",
                        "circuit_breaker_tripped": True,
                        "trip_reason": cb_result["reason"],
                        "metrics": accumulated_metrics,
                    }

        stage.status = "passed"
        stage.completed_at = datetime.now().isoformat()
        stage.metrics = accumulated_metrics

        final_error_rate = (
            accumulated_metrics["error_count"] / accumulated_metrics["total_requests"]
            if accumulated_metrics["total_requests"] > 0
            else 0
        )
        final_avg_latency = (
            accumulated_metrics["total_latency_ms"] / accumulated_metrics["total_requests"]
            if accumulated_metrics["total_requests"] > 0
            else 0
        )

        self.logger.info(
            f"灰度阶段 [{stage.name}] 通过 - 请求量: {accumulated_metrics['total_requests']}, "
            f"错误率: {final_error_rate:.4%}, 平均延迟: {final_avg_latency:.0f}ms"
        )

        return {
            "success": True,
            "message": f"灰度阶段 [{stage.name}] 验证通过",
            "circuit_breaker_tripped": False,
            "metrics": accumulated_metrics,
        }

    def _simulate_traffic(self, weight_percent: float) -> Dict[str, Any]:
        base_traffic = int(100 * (weight_percent / 100))
        requests = max(base_traffic, 10)
        error_rate = random.uniform(0.0, 0.03)
        errors = int(requests * error_rate)
        latencies = [random.uniform(50, 1500) for _ in range(requests)]

        return {
            "requests": requests,
            "errors": errors,
            "total_latency": sum(latencies),
            "max_latency": max(latencies),
            "avg_latency": sum(latencies) / len(latencies),
            "temp_anomalies": random.randint(0, 2),
        }

    def _evaluate_circuit_breaker(
        self,
        cb: CircuitBreaker,
        current_error_rate: float,
        current_avg_latency: float,
        error_threshold: float,
        latency_threshold: float,
        release_id: str,
    ) -> Dict[str, Any]:
        if cb.state == CircuitBreakerState.OPEN:
            half_open_interval = self.cb_config.get("half_open_interval_seconds", 30)
            if cb.last_failure_time:
                elapsed = (datetime.now() - datetime.fromisoformat(cb.last_failure_time)).total_seconds()
                if elapsed >= half_open_interval:
                    cb.state = CircuitBreakerState.HALF_OPEN
                    cb.half_open_retries += 1
                    self.logger.info(f"熔断器进入半开状态 [release_id={release_id}]")
                else:
                    return {
                        "tripped": True,
                        "reason": f"熔断器处于开启状态，等待恢复({elapsed:.0f}/{half_open_interval}s)",
                    }

        tripped = False
        reason = ""

        if current_error_rate > error_threshold:
            tripped = True
            reason = f"错误率超标({current_error_rate:.4%} > {error_threshold:.4%})"
        elif current_avg_latency > latency_threshold:
            tripped = True
            reason = f"延迟超标({current_avg_latency:.0f}ms > {latency_threshold}ms)"

        if tripped:
            cb.failure_count += 1
            cb.last_failure_time = datetime.now().isoformat()
            cb.state = CircuitBreakerState.OPEN
            cb.last_state_change = datetime.now().isoformat()
            self.logger.error(
                f"熔断器触发 [release_id={release_id}]: {reason}, "
                f"累计失败次数: {cb.failure_count}"
            )
        else:
            cb.success_count += 1
            if cb.state == CircuitBreakerState.HALF_OPEN:
                max_retries = self.cb_config.get("half_open_retry_count", 3)
                if cb.half_open_retries >= max_retries:
                    cb.state = CircuitBreakerState.CLOSED
                    cb.last_state_change = datetime.now().isoformat()
                    self.logger.info(f"熔断器恢复关闭状态 [release_id={release_id}]")

        return {"tripped": tripped, "reason": reason}

    def execute_rollback(
        self,
        release_id: str,
        from_version: str,
        snapshot: RollbackSnapshot,
        reason: str,
    ) -> Dict[str, Any]:
        self.logger.warning(
            f"执行智能回滚 [release_id={release_id}]: {from_version} -> {snapshot.version}, "
            f"原因: {reason}"
        )

        checksum_valid = self._verify_snapshot_integrity(snapshot)
        if not checksum_valid:
            self.logger.error(f"回滚快照校验失败 [release_id={release_id}], 快照可能被篡改")
            return {
                "success": False,
                "message": "回滚快照完整性校验失败，拒绝回滚",
            }

        health_endpoint = self.rollback_config.get("health_check_endpoint", "")
        health_timeout = self.rollback_config.get("health_check_timeout_seconds", 15)
        health_retries = self.rollback_config.get("health_check_retries", 3)

        self.logger.info(f"开始回滚至版本 {snapshot.version}...")
        time.sleep(0.2)

        self.logger.info("回滚部署完成，执行健康检查...")
        health_passed = self._perform_health_check(health_endpoint, health_timeout, health_retries)

        if not health_passed:
            self.logger.error(f"回滚后健康检查失败 [release_id={release_id}]")
            return {
                "success": False,
                "message": "回滚后健康检查失败，需要人工介入",
            }

        self.logger.info(
            f"智能回滚成功 [release_id={release_id}]: {from_version} -> {snapshot.version}"
        )

        return {
            "success": True,
            "message": f"已成功回滚至版本 {snapshot.version}",
            "from_version": from_version,
            "to_version": snapshot.version,
            "reason": reason,
            "health_check_passed": True,
            "snapshot_verified": True,
        }

    def _verify_snapshot_integrity(self, snapshot: RollbackSnapshot) -> bool:
        config_str = json.dumps(snapshot.config_snapshot, sort_keys=True, ensure_ascii=False)
        computed_checksum = hashlib.sha256(config_str.encode("utf-8")).hexdigest()
        return computed_checksum == snapshot.checksum

    def _perform_health_check(self, endpoint: str, timeout: int, retries: int) -> bool:
        self.logger.info(f"健康检查: endpoint={endpoint}, timeout={timeout}s, retries={retries}")

        for attempt in range(retries):
            self.logger.info(f"健康检查尝试 {attempt + 1}/{retries}...")
            time.sleep(0.1)

            is_healthy = random.random() > 0.1
            if is_healthy:
                self.logger.info("健康检查通过")
                return True

            self.logger.warning(f"健康检查第{attempt + 1}次失败")

        return False

    def get_canary_summary(self, stages: List[CanaryStage]) -> Dict[str, Any]:
        summary = {
            "total_stages": len(stages),
            "completed_stages": 0,
            "failed_stages": 0,
            "pending_stages": 0,
            "stage_details": [],
        }

        for stage in stages:
            detail = {
                "name": stage.name,
                "weight_percent": stage.weight_percent,
                "routes": stage.routes,
                "status": stage.status,
                "started_at": stage.started_at,
                "completed_at": stage.completed_at,
                "metrics": stage.metrics,
            }
            summary["stage_details"].append(detail)

            if stage.status == "passed":
                summary["completed_stages"] += 1
            elif stage.status == "failed":
                summary["failed_stages"] += 1
            else:
                summary["pending_stages"] += 1

        return summary
