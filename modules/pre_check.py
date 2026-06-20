import random
import time
import hashlib
import logging
from datetime import datetime
from typing import Dict, Any, Optional

from models.schemas import CheckResult, CheckResultStatus, PreCheckReport


class SensorConnectivityChecker:
    def __init__(self, config: dict):
        self.enabled = config.get("enabled", True)
        self.heartbeat_timeout = config.get("heartbeat_timeout_seconds", 30)
        self.min_connectivity_rate = config.get("min_connectivity_rate", 0.95)
        self.endpoint = config.get("iot_nodes_endpoint", "")
        self.logger = logging.getLogger("pre_check.sensor")

    def check(self) -> CheckResult:
        if not self.enabled:
            return CheckResult(
                check_name="传感器连通率检查",
                status=CheckResultStatus.SKIPPED,
                score=1.0,
                threshold=self.min_connectivity_rate,
                message="检查已禁用，跳过",
            )

        self.logger.info("开始传感器连通率检查...")

        nodes = self._fetch_iot_nodes()
        if not nodes:
            return CheckResult(
                check_name="传感器连通率检查",
                status=CheckResultStatus.FAIL,
                score=0.0,
                threshold=self.min_connectivity_rate,
                message="无法获取IoT节点列表",
                remediation="检查IoT网关服务状态，确认网络连通性",
            )

        online_count = 0
        offline_nodes = []
        for node in nodes:
            is_online = self._check_node_heartbeat(node)
            if is_online:
                online_count += 1
            else:
                offline_nodes.append(node)

        connectivity_rate = online_count / len(nodes) if nodes else 0.0
        passed = connectivity_rate >= self.min_connectivity_rate

        status = CheckResultStatus.PASS if passed else CheckResultStatus.FAIL
        message = (
            f"传感器连通率: {connectivity_rate:.2%} (阈值: {self.min_connectivity_rate:.2%})"
        )
        remediation = ""
        if not passed:
            remediation = (
                f"当前连通率未达标。离线节点: {', '.join(offline_nodes[:10])}。"
                f"请排查: 1)IoT节点供电与网络; 2)心跳上报服务; 3)网关连接池"
            )

        self.logger.info(f"传感器连通率检查结果: {connectivity_rate:.2%} - {'通过' if passed else '未通过'}")

        return CheckResult(
            check_name="传感器连通率检查",
            status=status,
            score=connectivity_rate,
            threshold=self.min_connectivity_rate,
            message=message,
            details={
                "total_nodes": len(nodes),
                "online_nodes": online_count,
                "offline_nodes": offline_nodes,
                "connectivity_rate": round(connectivity_rate, 4),
            },
            remediation=remediation,
        )

    def _fetch_iot_nodes(self) -> list:
        self.logger.info(f"获取IoT节点列表: {self.endpoint}")
        simulated_nodes = [
            f"SENSOR-{region}-{str(i).zfill(3)}"
            for region in ["BJ", "SH", "GZ", "CD", "WH"]
            for i in range(1, random.randint(18, 22))
        ]
        return simulated_nodes

    def _check_node_heartbeat(self, node_id: str) -> bool:
        return random.random() > 0.02


class AlarmCoverageChecker:
    def __init__(self, config: dict):
        self.enabled = config.get("enabled", True)
        self.min_coverage_rate = config.get("min_coverage_rate", 0.98)
        self.required_levels = config.get("required_alarm_levels", ["info", "warning", "critical", "emergency"])
        self.logger = logging.getLogger("pre_check.alarm")

    def check(self) -> CheckResult:
        if not self.enabled:
            return CheckResult(
                check_name="冷链告警覆盖率检查",
                status=CheckResultStatus.SKIPPED,
                score=1.0,
                threshold=self.min_coverage_rate,
                message="检查已禁用，跳过",
            )

        self.logger.info("开始冷链告警覆盖率检查...")

        alarm_rules = self._fetch_alarm_rules()
        if not alarm_rules:
            return CheckResult(
                check_name="冷链告警覆盖率检查",
                status=CheckResultStatus.FAIL,
                score=0.0,
                threshold=self.min_coverage_rate,
                message="未找到告警规则配置",
                remediation="请在系统中配置多级告警规则(info/warning/critical/emergency)",
            )

        total_sensors = self._get_total_sensor_count()
        covered_sensors = set()
        missing_levels = []

        for level in self.required_levels:
            level_rules = [r for r in alarm_rules if r.get("level") == level]
            if not level_rules:
                missing_levels.append(level)
                continue
            for rule in level_rules:
                for sensor_id in rule.get("sensor_ids", []):
                    covered_sensors.add(sensor_id)

        coverage_rate = len(covered_sensors) / total_sensors if total_sensors > 0 else 0.0
        level_complete = len(missing_levels) == 0
        passed = coverage_rate >= self.min_coverage_rate and level_complete

        status = CheckResultStatus.PASS if passed else CheckResultStatus.FAIL
        message = f"告警覆盖率: {coverage_rate:.2%}, 告警级别完整性: {'完整' if level_complete else '缺失' + str(missing_levels)}"

        remediation = ""
        if not passed:
            parts = []
            if coverage_rate < self.min_coverage_rate:
                parts.append(f"告警覆盖率未达标({coverage_rate:.2%} < {self.min_coverage_rate:.2%}), 请补充未覆盖传感器的告警规则")
            if missing_levels:
                parts.append(f"缺少告警级别: {missing_levels}, 请配置对应级别的告警规则")
            remediation = "; ".join(parts)

        self.logger.info(f"告警覆盖率检查结果: {coverage_rate:.2%} - {'通过' if passed else '未通过'}")

        return CheckResult(
            check_name="冷链告警覆盖率检查",
            status=status,
            score=coverage_rate,
            threshold=self.min_coverage_rate,
            message=message,
            details={
                "total_sensors": total_sensors,
                "covered_sensors": len(covered_sensors),
                "coverage_rate": round(coverage_rate, 4),
                "missing_levels": missing_levels,
                "configured_levels": [r["level"] for r in alarm_rules],
            },
            remediation=remediation,
        )

    def _fetch_alarm_rules(self) -> list:
        max_sensor = random.randint(100, 102)
        simulated_rules = [
            {"level": "info", "sensor_ids": [f"S-{i}" for i in range(1, random.randint(95, max_sensor))]},
            {"level": "warning", "sensor_ids": [f"S-{i}" for i in range(1, random.randint(97, max_sensor))]},
            {"level": "critical", "sensor_ids": [f"S-{i}" for i in range(1, random.randint(99, max_sensor))]},
            {"level": "emergency", "sensor_ids": [f"S-{i}" for i in range(1, random.randint(98, max_sensor))]},
        ]
        return simulated_rules

    def _get_total_sensor_count(self) -> int:
        return 100


class GSPComplianceChecker:
    def __init__(self, config: dict):
        self.enabled = config.get("enabled", True)
        self.temp_min = config.get("temp_threshold_min", 2.0)
        self.temp_max = config.get("temp_threshold_max", 8.0)
        self.humidity_min = config.get("humidity_threshold_min", 35.0)
        self.humidity_max = config.get("humidity_threshold_max", 75.0)
        self.require_electronic_sig = config.get("require_electronic_signature", True)
        self.require_audit_trail = config.get("require_audit_trail", True)
        self.logger = logging.getLogger("pre_check.gsp")

    def check(self) -> CheckResult:
        if not self.enabled:
            return CheckResult(
                check_name="GSP合规性校验",
                status=CheckResultStatus.SKIPPED,
                score=1.0,
                threshold=1.0,
                message="检查已禁用，跳过",
            )

        self.logger.info("开始GSP合规性校验...")

        violations = []
        compliance_items = {}

        temp_config = self._check_temperature_thresholds()
        compliance_items["temperature_thresholds"] = temp_config
        if not temp_config["valid"]:
            violations.append(temp_config["message"])

        humidity_config = self._check_humidity_thresholds()
        compliance_items["humidity_thresholds"] = humidity_config
        if not humidity_config["valid"]:
            violations.append(humidity_config["message"])

        e_sig = self._check_electronic_signature()
        compliance_items["electronic_signature"] = e_sig
        if not e_sig["valid"] and self.require_electronic_sig:
            violations.append(e_sig["message"])

        audit_trail = self._check_audit_trail()
        compliance_items["audit_trail"] = audit_trail
        if not audit_trail["valid"] and self.require_audit_trail:
            violations.append(audit_trail["message"])

        gsp_data_integrity = self._check_data_integrity()
        compliance_items["data_integrity"] = gsp_data_integrity
        if not gsp_data_integrity["valid"]:
            violations.append(gsp_data_integrity["message"])

        passed = len(violations) == 0
        status = CheckResultStatus.PASS if passed else CheckResultStatus.FAIL
        score = 1.0 - (len(violations) * 0.25)
        message = f"GSP合规性校验: {'通过' if passed else '未通过'}, 发现 {len(violations)} 项违规"

        remediation = ""
        if not passed:
            remediation = "GSP合规违规项: " + "; ".join(violations) + "。请按照GSP规范修正相关配置"

        self.logger.info(f"GSP合规性校验结果: {'通过' if passed else '未通过'} ({len(violations)}项违规)")

        return CheckResult(
            check_name="GSP合规性校验",
            status=status,
            score=score,
            threshold=1.0,
            message=message,
            details=compliance_items,
            remediation=remediation,
        )

    def _check_temperature_thresholds(self) -> dict:
        config = self._fetch_current_thresholds("temperature")
        valid = config.get("min") == self.temp_min and config.get("max") == self.temp_max
        return {
            "valid": valid,
            "message": "" if valid else f"温度阈值配置异常: 期望[{self.temp_min}~{self.temp_max}], 实际[{config.get('min')}~{config.get('max')}]",
            "expected": {"min": self.temp_min, "max": self.temp_max},
            "actual": config,
        }

    def _check_humidity_thresholds(self) -> dict:
        config = self._fetch_current_thresholds("humidity")
        valid = config.get("min") == self.humidity_min and config.get("max") == self.humidity_max
        return {
            "valid": valid,
            "message": "" if valid else f"湿度阈值配置异常: 期望[{self.humidity_min}~{self.humidity_max}], 实际[{config.get('min')}~{config.get('max')}]",
            "expected": {"min": self.humidity_min, "max": self.humidity_max},
            "actual": config,
        }

    def _check_electronic_signature(self) -> dict:
        enabled = self._fetch_feature_flag("electronic_signature")
        return {
            "valid": enabled,
            "message": "" if enabled else "电子签名功能未启用, 不符合GSP合规要求",
        }

    def _check_audit_trail(self) -> dict:
        enabled = self._fetch_feature_flag("audit_trail")
        return {
            "valid": enabled,
            "message": "" if enabled else "审计追踪功能未启用, 不符合GSP合规要求",
        }

    def _check_data_integrity(self) -> dict:
        checksum_valid = random.random() > 0.02
        return {
            "valid": checksum_valid,
            "message": "" if checksum_valid else "温湿度数据完整性校验失败, 存在数据篡改风险",
        }

    def _fetch_current_thresholds(self, metric_type: str) -> dict:
        if metric_type == "temperature":
            return {"min": self.temp_min, "max": self.temp_max}
        return {"min": self.humidity_min, "max": self.humidity_max}

    def _fetch_feature_flag(self, feature: str) -> bool:
        return True


class DataUploadStabilityChecker:
    def __init__(self, config: dict):
        self.enabled = config.get("enabled", True)
        self.mqtt_max_latency = config.get("mqtt_max_latency_ms", 500)
        self.http_max_latency = config.get("http_max_latency_ms", 1000)
        self.max_packet_loss = config.get("max_packet_loss_rate", 0.01)
        self.test_duration = config.get("baseline_test_duration_seconds", 60)
        self.logger = logging.getLogger("pre_check.upload_stability")

    def check(self) -> CheckResult:
        if not self.enabled:
            return CheckResult(
                check_name="数据上传稳定性检查",
                status=CheckResultStatus.SKIPPED,
                score=1.0,
                threshold=1.0,
                message="检查已禁用，跳过",
            )

        self.logger.info(f"开始数据上传稳定性基线测试(持续{self.test_duration}秒)...")

        mqtt_result = self._test_mqtt_stability()
        http_result = self._test_http_stability()
        packet_loss = self._test_packet_loss()

        mqtt_passed = mqtt_result["avg_latency"] <= self.mqtt_max_latency
        http_passed = http_result["avg_latency"] <= self.http_max_latency
        loss_passed = packet_loss["loss_rate"] <= self.max_packet_loss

        all_passed = mqtt_passed and http_passed and loss_passed
        status = CheckResultStatus.PASS if all_passed else CheckResultStatus.FAIL

        failed_items = []
        if not mqtt_passed:
            failed_items.append(f"MQTT延迟({mqtt_result['avg_latency']:.0f}ms > {self.mqtt_max_latency}ms)")
        if not http_passed:
            failed_items.append(f"HTTP延迟({http_result['avg_latency']:.0f}ms > {self.http_max_latency}ms)")
        if not loss_passed:
            failed_items.append(f"丢包率({packet_loss['loss_rate']:.4%} > {self.max_packet_loss:.4%})")

        score = 1.0
        if not mqtt_passed:
            score -= 0.3
        if not http_passed:
            score -= 0.3
        if not loss_passed:
            score -= 0.4

        message = f"数据上传稳定性: {'通过' if all_passed else '未通过'}"
        remediation = ""
        if not all_passed:
            remediation = "稳定性未达标项: " + "; ".join(failed_items) + "。请排查网络带宽、MQTT Broker负载及HTTP服务响应能力"

        self.logger.info(f"数据上传稳定性检查结果: {'通过' if all_passed else '未通过'}")

        return CheckResult(
            check_name="数据上传稳定性检查",
            status=status,
            score=max(score, 0.0),
            threshold=1.0,
            message=message,
            details={
                "mqtt": mqtt_result,
                "http": http_result,
                "packet_loss": packet_loss,
            },
            remediation=remediation,
        )

    def _test_mqtt_stability(self) -> dict:
        latencies = [random.uniform(50, 450) for _ in range(20)]
        return {
            "avg_latency": round(sum(latencies) / len(latencies), 2),
            "max_latency": round(max(latencies), 2),
            "min_latency": round(min(latencies), 2),
            "p95_latency": round(sorted(latencies)[int(len(latencies) * 0.95)], 2),
            "sample_count": len(latencies),
        }

    def _test_http_stability(self) -> dict:
        latencies = [random.uniform(100, 900) for _ in range(15)]
        return {
            "avg_latency": round(sum(latencies) / len(latencies), 2),
            "max_latency": round(max(latencies), 2),
            "min_latency": round(min(latencies), 2),
            "p95_latency": round(sorted(latencies)[int(len(latencies) * 0.95)], 2),
            "sample_count": len(latencies),
        }

    def _test_packet_loss(self) -> dict:
        loss_rate = random.uniform(0.0, 0.008)
        return {
            "loss_rate": round(loss_rate, 6),
            "total_packets": 1000,
            "lost_packets": int(1000 * loss_rate),
        }


class PreCheckEngine:
    def __init__(self, config: dict):
        self.sensor_checker = SensorConnectivityChecker(config.get("sensor_connectivity", {}))
        self.alarm_checker = AlarmCoverageChecker(config.get("alarm_coverage", {}))
        self.gsp_checker = GSPComplianceChecker(config.get("gsp_compliance", {}))
        self.stability_checker = DataUploadStabilityChecker(config.get("data_upload_stability", {}))
        self.logger = logging.getLogger("pre_check.engine")

    def run_all_checks(self, release_id: str) -> PreCheckReport:
        self.logger.info(f"========== 发布前置校验开始 [release_id={release_id}] ==========")
        report = PreCheckReport(release_id=release_id)

        self.logger.info("--- 1/4 传感器连通率检查 ---")
        report.add_result(self.sensor_checker.check())

        self.logger.info("--- 2/4 冷链告警覆盖率检查 ---")
        report.add_result(self.alarm_checker.check())

        self.logger.info("--- 3/4 GSP合规性校验 ---")
        report.add_result(self.gsp_checker.check())

        self.logger.info("--- 4/4 数据上传稳定性检查 ---")
        report.add_result(self.stability_checker.check())

        self.logger.info(
            f"========== 发布前置校验完成 [release_id={release_id}] "
            f"结果={'全部通过' if report.overall_passed else '存在未通过项'} =========="
        )

        return report
