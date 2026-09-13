#!/usr/bin/env python3
"""
PUSHPAK Grand Challenge 2026
Grand Challenge 3 - Security of Drones
Objective 2 - Drone Intrusion Detection System
Stage 1 Proof-of-Concept

Demonstrates:
- Drone telemetry modeling and physics simulation
- Feature extraction (kinematic, network, rate-based)
- Deterministic normal-flight and attack-injection scenarios
- Modular rule-based multi-vector anomaly detection:
    * GPS spoofing
    * MAVLink rate anomaly
    * Command flooding / injection anomaly
    * Telemetry manipulation & sensor disagreement
    * Denial-of-Service (DoS) anomaly
- Firmware SHA-256 integrity verification
- Cryptographic hash-chained tamper-evident event logging
- Latency & detection benchmarking with JSON reporting
- Comprehensive self-test suite

Standard library only — zero external dependencies required.

Usage:
    python stage1_drone_ids.py
    python stage1_drone_ids.py --duration 10.0
    python stage1_drone_ids.py --scenario GPS_SPOOFING
    python stage1_drone_ids.py --self-test
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple


# ============================================================
# 1. CONFIGURATION
# ============================================================

@dataclass
class IDSConfig:
    """Configurable thresholds for rule-based detection."""
    gps_speed_difference_mps: float = 18.0
    message_rate_high: float = 40.0
    command_rate_high: float = 12.0
    sensor_altitude_disagreement_m: float = 30.0
    dos_multiplier: float = 1.5


DEFAULT_CONFIG = IDSConfig()


# ============================================================
# 2. DATA MODELS
# ============================================================

@dataclass
class DroneTelemetry:
    """Represents a single telemetry frame received from the drone."""
    timestamp: float
    latitude: float
    longitude: float
    gps_speed: float
    ground_speed: float
    altitude: float
    heading: float
    satellites: int
    hdop: float
    roll: float
    pitch: float
    battery_voltage: float
    flight_mode: str
    message_type: str
    message_rate: float
    command_count: int
    source: str = "stage1_simulator"
    scenario: str = "NORMAL"
    expected_attack: str = "NONE"


@dataclass
class FeatureVector:
    """Engineered features extracted from consecutive telemetry frames."""
    speed_difference: float
    position_change_m: float
    heading_change_deg: float
    altitude_change_m: float
    gps_quality_score: float
    message_rate: float
    command_rate: float
    sensor_speed_disagreement: float
    sensor_altitude_disagreement: float


@dataclass
class SecurityAlert:
    """Security alert raised when an anomaly or attack pattern is detected."""
    timestamp: float
    attack_type: str
    category: str
    severity: str
    confidence: float
    source: str
    evidence: Dict[str, Any]
    processing_latency_ms: float = 0.0


@dataclass
class ScenarioResult:
    """Results from evaluating a single flight scenario."""
    scenario: str
    expected_attack: str
    detected_attack: str
    passed: bool
    processing_latency_ms: float


# ============================================================
# 3. GEOMETRY / TELEMETRY UTILITIES
# ============================================================

EARTH_RADIUS_M: float = 6_371_000.0


def haversine_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculate great-circle distance between two GPS coordinates in metres."""
    p1 = math.radians(lat1)
    p2 = math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)

    a = (
        math.sin(dphi / 2.0) ** 2
        + math.cos(p1) * math.cos(p2) * math.sin(dlambda / 2.0) ** 2
    )
    a = max(0.0, min(1.0, a))
    return 2.0 * EARTH_RADIUS_M * math.asin(math.sqrt(a))


def angle_difference_deg(a: float, b: float) -> float:
    """Calculate the smallest absolute difference between two angles in degrees."""
    return abs((a - b + 180.0) % 360.0 - 180.0)


# ============================================================
# 4. NORMAL-FLIGHT SIMULATOR
# ============================================================

class NormalFlightSimulator:
    """Generates realistic, deterministic normal-flight drone telemetry."""

    def __init__(
        self,
        duration_s: float = 5.0,
        sample_period_s: float = 0.1,
        seed: int = 42,
        start_lat: float = 19.1330,
        start_lon: float = 72.9150,
    ) -> None:
        if duration_s <= 0:
            raise ValueError("duration_s must be greater than zero.")
        if sample_period_s <= 0:
            raise ValueError("sample_period_s must be greater than zero.")

        self.duration_s = duration_s
        self.sample_period_s = sample_period_s
        self.rng = random.Random(seed)
        self.start_lat = start_lat
        self.start_lon = start_lon

    def generate(self) -> List[DroneTelemetry]:
        count = int(round(self.duration_s / self.sample_period_s))
        lat = self.start_lat
        lon = self.start_lon
        records: List[DroneTelemetry] = []

        for i in range(count):
            t = i * self.sample_period_s

            ground_speed = 8.0 + 0.45 * math.sin(t / 3.5) + self.rng.uniform(-0.08, 0.08)
            gps_speed = ground_speed + self.rng.uniform(-0.12, 0.12)
            heading = 35.0 + 4.0 * math.sin(t / 5.0) + self.rng.uniform(-0.3, 0.3)
            altitude = 40.0 + math.sin(t / 4.5) + self.rng.uniform(-0.05, 0.05)

            north_m = ground_speed * self.sample_period_s * math.cos(math.radians(heading))
            east_m = ground_speed * self.sample_period_s * math.sin(math.radians(heading))

            lat += north_m / 111_320.0
            lon += east_m / (111_320.0 * max(math.cos(math.radians(lat)), 0.2))

            records.append(
                DroneTelemetry(
                    timestamp=t,
                    latitude=lat,
                    longitude=lon,
                    gps_speed=max(gps_speed, 0.0),
                    ground_speed=max(ground_speed, 0.0),
                    altitude=altitude,
                    heading=heading % 360.0,
                    satellites=12 + self.rng.choice([-1, 0, 0, 0, 1]),
                    hdop=max(0.55, 0.90 + self.rng.uniform(-0.08, 0.08)),
                    roll=1.5 * math.sin(t / 2.5),
                    pitch=1.2 * math.sin(t / 3.0),
                    battery_voltage=16.4 - 0.005 * t,
                    flight_mode="GUIDED",
                    message_type="GLOBAL_POSITION_INT",
                    message_rate=10.0 + self.rng.uniform(-0.3, 0.3),
                    command_count=i // 10,
                )
            )

        return records


# ============================================================
# 5. CONTROLLED TEST SCENARIOS
# ============================================================

def base_flight(seed: int = 42) -> List[DroneTelemetry]:
    return NormalFlightSimulator(duration_s=5.0, sample_period_s=0.1, seed=seed).generate()


def _inject_attack(
    seed: int,
    attack_name: str,
    override_fn: Callable[[DroneTelemetry, int, int], Dict[str, Any]],
) -> List[DroneTelemetry]:
    """Helper to inject attack modifications halfway through a baseline flight."""
    data = base_flight(seed)
    start = max(1, len(data) // 2)

    for i in range(start, len(data)):
        item = data[i]
        overrides = override_fn(item, i, start)
        overrides["scenario"] = attack_name
        overrides["expected_attack"] = attack_name
        data[i] = DroneTelemetry(**{**asdict(item), **overrides})

    return data


def normal_scenario(seed: int = 42) -> List[DroneTelemetry]:
    return base_flight(seed)


def gps_spoofing_scenario(seed: int = 42) -> List[DroneTelemetry]:
    return _inject_attack(
        seed,
        "GPS_SPOOFING",
        lambda item, i, start: {"gps_speed": 45.0},
    )


def mavlink_anomaly_scenario(seed: int = 42) -> List[DroneTelemetry]:
    return _inject_attack(
        seed,
        "MAVLINK_ANOMALY",
        lambda item, i, start: {"message_rate": 70.0},
    )


def command_anomaly_scenario(seed: int = 42) -> List[DroneTelemetry]:
    data = base_flight(seed)
    start = max(1, len(data) // 2)
    baseline = data[start - 1].command_count

    return _inject_attack(
        seed,
        "COMMAND_ANOMALY",
        lambda item, i, start: {"command_count": baseline + 50 * (i - start + 1)},
    )


def telemetry_manipulation_scenario(seed: int = 42) -> List[DroneTelemetry]:
    return _inject_attack(
        seed,
        "TELEMETRY_MANIPULATION",
        lambda item, i, start: {"gps_speed": 35.0, "ground_speed": 8.0},
    )


def dos_scenario(seed: int = 42) -> List[DroneTelemetry]:
    return _inject_attack(
        seed,
        "DOS_ANOMALY",
        lambda item, i, start: {"message_rate": 100.0},
    )


SCENARIOS: Dict[str, Callable[[int], List[DroneTelemetry]]] = {
    "NORMAL": normal_scenario,
    "GPS_SPOOFING": gps_spoofing_scenario,
    "MAVLINK_ANOMALY": mavlink_anomaly_scenario,
    "COMMAND_ANOMALY": command_anomaly_scenario,
    "TELEMETRY_MANIPULATION": telemetry_manipulation_scenario,
    "DOS_ANOMALY": dos_scenario,
}


# ============================================================
# 6. FEATURE ENGINE
# ============================================================

class FeatureEngine:
    """Extracts kinematic, network, and sensor consistency features."""

    def __init__(self) -> None:
        self.previous: Optional[DroneTelemetry] = None

    def reset(self) -> None:
        self.previous = None

    def extract(self, current: DroneTelemetry) -> FeatureVector:
        if self.previous is None:
            speed_difference = abs(current.gps_speed - current.ground_speed)
            self.previous = current
            return FeatureVector(
                speed_difference=speed_difference,
                position_change_m=0.0,
                heading_change_deg=0.0,
                altitude_change_m=0.0,
                gps_quality_score=self.gps_quality(current),
                message_rate=current.message_rate,
                command_rate=0.0,
                sensor_speed_disagreement=speed_difference,
                sensor_altitude_disagreement=0.0,
            )

        dt = max(current.timestamp - self.previous.timestamp, 1e-6)
        command_delta = max(0, current.command_count - self.previous.command_count)
        speed_difference = abs(current.gps_speed - current.ground_speed)
        altitude_change = abs(current.altitude - self.previous.altitude)
        position_change = haversine_m(
            self.previous.latitude, self.previous.longitude,
            current.latitude, current.longitude,
        )
        heading_change = angle_difference_deg(current.heading, self.previous.heading)

        features = FeatureVector(
            speed_difference=speed_difference,
            position_change_m=position_change,
            heading_change_deg=heading_change,
            altitude_change_m=altitude_change,
            gps_quality_score=self.gps_quality(current),
            message_rate=current.message_rate,
            command_rate=command_delta / dt,
            sensor_speed_disagreement=speed_difference,
            sensor_altitude_disagreement=altitude_change,
        )
        self.previous = current
        return features

    @staticmethod
    def gps_quality(telemetry: DroneTelemetry) -> float:
        satellite_score = max(0.0, min(1.0, (telemetry.satellites - 4) / 8.0))
        hdop_score = max(0.0, min(1.0, 2.0 / max(telemetry.hdop, 0.1)))
        return satellite_score * hdop_score


# ============================================================
# 7. DETECTORS
# ============================================================

class BaseDetector:
    """Base interface for intrusion detectors."""
    def detect(self, telemetry: DroneTelemetry, features: FeatureVector) -> List[SecurityAlert]:
        raise NotImplementedError


class GPSDetector(BaseDetector):
    def __init__(self, config: IDSConfig = DEFAULT_CONFIG) -> None:
        self.config = config

    def detect(self, telemetry: DroneTelemetry, features: FeatureVector) -> List[SecurityAlert]:
        threshold = self.config.gps_speed_difference_mps
        if features.speed_difference > threshold:
            confidence = min(0.99, 0.70 + (features.speed_difference - threshold) / 100.0)
            return [
                SecurityAlert(
                    timestamp=telemetry.timestamp,
                    attack_type="GPS_SPOOFING",
                    category="navigation",
                    severity="HIGH",
                    confidence=confidence,
                    source="GPSDetector",
                    evidence={
                        "gps_speed": telemetry.gps_speed,
                        "ground_speed": telemetry.ground_speed,
                        "speed_difference": features.speed_difference,
                        "satellites": telemetry.satellites,
                        "hdop": telemetry.hdop,
                    },
                )
            ]
        return []


class MAVLinkDetector(BaseDetector):
    def __init__(self, config: IDSConfig = DEFAULT_CONFIG) -> None:
        self.config = config

    def detect(self, telemetry: DroneTelemetry, features: FeatureVector) -> List[SecurityAlert]:
        threshold = self.config.message_rate_high
        if features.message_rate > threshold:
            confidence = min(0.99, 0.75 + (features.message_rate - threshold) / 200.0)
            return [
                SecurityAlert(
                    timestamp=telemetry.timestamp,
                    attack_type="MAVLINK_ANOMALY",
                    category="communication",
                    severity="HIGH",
                    confidence=confidence,
                    source="MAVLinkDetector",
                    evidence={
                        "message_rate": features.message_rate,
                        "message_type": telemetry.message_type,
                    },
                )
            ]
        return []


class CommandDetector(BaseDetector):
    def __init__(self, config: IDSConfig = DEFAULT_CONFIG) -> None:
        self.config = config

    def detect(self, telemetry: DroneTelemetry, features: FeatureVector) -> List[SecurityAlert]:
        threshold = self.config.command_rate_high
        if features.command_rate > threshold:
            confidence = min(0.99, 0.75 + (features.command_rate - threshold) / 100.0)
            return [
                SecurityAlert(
                    timestamp=telemetry.timestamp,
                    attack_type="COMMAND_ANOMALY",
                    category="control",
                    severity="HIGH",
                    confidence=confidence,
                    source="CommandDetector",
                    evidence={
                        "command_rate": features.command_rate,
                        "flight_mode": telemetry.flight_mode,
                    },
                )
            ]
        return []


class TelemetryConsistencyDetector(BaseDetector):
    def __init__(self, config: IDSConfig = DEFAULT_CONFIG) -> None:
        self.config = config

    def detect(self, telemetry: DroneTelemetry, features: FeatureVector) -> List[SecurityAlert]:
        speed_limit = self.config.gps_speed_difference_mps
        altitude_limit = self.config.sensor_altitude_disagreement_m

        speed_bad = features.sensor_speed_disagreement > speed_limit
        altitude_bad = features.sensor_altitude_disagreement > altitude_limit

        if speed_bad or altitude_bad:
            confidence = 0.94 if (speed_bad and altitude_bad) else 0.82
            return [
                SecurityAlert(
                    timestamp=telemetry.timestamp,
                    attack_type="TELEMETRY_MANIPULATION",
                    category="telemetry",
                    severity="HIGH",
                    confidence=confidence,
                    source="TelemetryConsistencyDetector",
                    evidence={
                        "speed_disagreement": features.sensor_speed_disagreement,
                        "altitude_disagreement": features.sensor_altitude_disagreement,
                    },
                )
            ]
        return []


class DOSDetector(BaseDetector):
    def __init__(self, config: IDSConfig = DEFAULT_CONFIG) -> None:
        self.config = config

    def detect(self, telemetry: DroneTelemetry, features: FeatureVector) -> List[SecurityAlert]:
        dos_threshold = self.config.message_rate_high * self.config.dos_multiplier
        if features.message_rate > dos_threshold:
            confidence = min(0.99, 0.80 + (features.message_rate - dos_threshold) / 300.0)
            return [
                SecurityAlert(
                    timestamp=telemetry.timestamp,
                    attack_type="DOS_ANOMALY",
                    category="communication",
                    severity="HIGH",
                    confidence=confidence,
                    source="DOSDetector",
                    evidence={
                        "message_rate": features.message_rate,
                        "configured_threshold": dos_threshold,
                    },
                )
            ]
        return []


# ============================================================
# 8. DETECTION ENGINE
# ============================================================

class DetectionEngine:
    """Orchestrates feature extraction and multi-vector anomaly detection."""

    def __init__(
        self,
        config: IDSConfig = DEFAULT_CONFIG,
        detectors: Optional[List[BaseDetector]] = None,
    ) -> None:
        self.config = config
        self.feature_engine = FeatureEngine()
        self.detectors: List[BaseDetector] = detectors or [
            GPSDetector(config),
            MAVLinkDetector(config),
            CommandDetector(config),
            TelemetryConsistencyDetector(config),
            DOSDetector(config),
        ]

    def reset(self) -> None:
        self.feature_engine.reset()

    def process(self, telemetry: DroneTelemetry) -> Tuple[List[SecurityAlert], float]:
        start = time.perf_counter()
        features = self.feature_engine.extract(telemetry)

        alerts: List[SecurityAlert] = []
        for detector in self.detectors:
            alerts.extend(detector.detect(telemetry, features))

        latency_ms = (time.perf_counter() - start) * 1000.0
        for alert in alerts:
            alert.processing_latency_ms = latency_ms

        return alerts, latency_ms


# ============================================================
# 9. FIRMWARE INTEGRITY
# ============================================================

def sha256_file(path: Path) -> str:
    """Compute SHA-256 digest of a file in 1MB chunks."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def verify_firmware(firmware_path: Path, expected_hash: str) -> Dict[str, Any]:
    """Verify integrity of a drone firmware binary against a known SHA-256 digest."""
    actual_hash = sha256_file(firmware_path)
    return {
        "firmware_path": str(firmware_path),
        "expected_sha256": expected_hash.lower(),
        "actual_sha256": actual_hash,
        "integrity_ok": actual_hash == expected_hash.lower(),
    }


# ============================================================
# 10. HASH-CHAINED EVENT LOGGER
# ============================================================

class HashChainedEventLogger:
    """Tamper-evident event log where each record includes the SHA-256 of the prior record."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.previous_hash = self._load_previous_hash()

    def _load_previous_hash(self) -> str:
        if not self.path.exists():
            return "0" * 64

        last_record = None
        try:
            with self.path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    line_str = line.strip()
                    if line_str:
                        last_record = json.loads(line_str)
        except (OSError, json.JSONDecodeError):
            return "0" * 64

        if not last_record:
            return "0" * 64

        return str(last_record.get("record_hash", "0" * 64))

    @staticmethod
    def canonical(record: Dict[str, Any]) -> bytes:
        return json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def write(self, event: Dict[str, Any]) -> Dict[str, Any]:
        record = dict(event)
        record["previous_hash"] = self.previous_hash
        record_hash = hashlib.sha256(self.canonical(record)).hexdigest()
        record["record_hash"] = record_hash

        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")

        self.previous_hash = record_hash
        return record


# ============================================================
# 11. BENCHMARKING
# ============================================================

def run_scenario(
    name: str,
    scenario_factory: Callable[[int], List[DroneTelemetry]],
    seed: int = 42,
    config: IDSConfig = DEFAULT_CONFIG,
) -> ScenarioResult:
    """Execute a single scenario through the IDS and evaluate detection success."""
    engine = DetectionEngine(config=config)
    stream = scenario_factory(seed)
    expected = stream[-1].expected_attack if stream else "NONE"

    detected_types: set[str] = set()
    total_latency = 0.0
    samples = len(stream)

    for telemetry in stream:
        alerts, latency = engine.process(telemetry)
        total_latency += latency
        for alert in alerts:
            detected_types.add(alert.attack_type)

    average_latency = (total_latency / samples) if samples else 0.0

    if expected == "NONE":
        passed = len(detected_types) == 0
        detected_attack = "NONE"
    else:
        passed = expected in detected_types
        detected_attack = expected if passed else (sorted(detected_types)[0] if detected_types else "NONE")

    return ScenarioResult(
        scenario=name,
        expected_attack=expected,
        detected_attack=detected_attack,
        passed=passed,
        processing_latency_ms=average_latency,
    )


def benchmark_all(config: IDSConfig = DEFAULT_CONFIG) -> Dict[str, Any]:
    """Run all scenarios through the benchmark suite and calculate key metrics."""
    results: List[ScenarioResult] = [
        run_scenario(name, factory, seed=42, config=config)
        for name, factory in SCENARIOS.items()
    ]

    attack_cases = [r for r in results if r.expected_attack != "NONE"]
    normal_cases = [r for r in results if r.expected_attack == "NONE"]

    detection_rate = (
        sum(r.passed for r in attack_cases) / len(attack_cases)
        if attack_cases else 1.0
    )
    false_positive_rate = (
        sum(not r.passed for r in normal_cases) / len(normal_cases)
        if normal_cases else 0.0
    )
    average_latency = (
        sum(r.processing_latency_ms for r in results) / len(results)
        if results else 0.0
    )
    coverage = sum(r.passed for r in attack_cases)

    return {
        "results": [asdict(r) for r in results],
        "attack_detection_rate": detection_rate,
        "false_positive_rate": false_positive_rate,
        "average_processing_latency_ms": average_latency,
        "attack_vector_coverage": coverage,
        "attack_vector_total": len(attack_cases),
    }


# ============================================================
# 12. DATASET / REPORT OUTPUT
# ============================================================

def save_jsonl(records: Iterable[Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            data = asdict(record) if hasattr(record, "__dataclass_fields__") else record
            handle.write(json.dumps(data, separators=(",", ":")) + "\n")


def save_report(report: Dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")


# ============================================================
# 13. FIRMWARE DEMO
# ============================================================

def run_firmware_demo(output_dir: Path) -> Dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    trusted = output_dir / "firmware_trusted.bin"
    modified = output_dir / "firmware_modified.bin"

    trusted.write_bytes(b"STAGE1-FIRMWARE\nVERSION=1.0\n")
    modified.write_bytes(b"STAGE1-FIRMWARE\nVERSION=1.0\nCONTROLLED-MODIFICATION\n")

    trusted_hash = sha256_file(trusted)
    trusted_check = verify_firmware(trusted, trusted_hash)
    modified_check = verify_firmware(modified, trusted_hash)

    return {
        "trusted": trusted_check,
        "modified": modified_check,
        "mismatch_detected": not modified_check["integrity_ok"],
    }


# ============================================================
# 14. SELF TESTS
# ============================================================

def self_test() -> None:
    """Verify correctness of feature extraction, each detector, and firmware checks."""
    engine = FeatureEngine()
    first = engine.extract(normal_scenario()[0])
    assert first.position_change_m == 0.0, "FeatureEngine init failed."

    # Validate each attack vector
    test_cases = [
        ("GPS_SPOOFING", gps_spoofing_scenario(), "GPS detector failed"),
        ("MAVLINK_ANOMALY", mavlink_anomaly_scenario(), "MAVLink detector failed"),
        ("COMMAND_ANOMALY", command_anomaly_scenario(), "Command detector failed"),
        ("TELEMETRY_MANIPULATION", telemetry_manipulation_scenario(), "Telemetry detector failed"),
        ("DOS_ANOMALY", dos_scenario(), "DoS detector failed"),
    ]

    for expected_type, stream, error_msg in test_cases:
        det_engine = DetectionEngine()
        found = False
        for item in stream:
            alerts, _ = det_engine.process(item)
            if any(a.attack_type == expected_type for a in alerts):
                found = True
                break
        assert found, error_msg

    # Firmware validation
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "firmware.bin"
        p.write_bytes(b"TEST-FIRMWARE")
        good_hash = sha256_file(p)
        assert verify_firmware(p, good_hash)["integrity_ok"]
        assert not verify_firmware(p, "0" * 64)["integrity_ok"]

    print("[PASS] All self-tests passed successfully.")


# ============================================================
# 15. COMPLETE STAGE 1 DEMO
# ============================================================

def run_stage1_demo(duration: float = 5.0, output_root: Path = Path("stage1_output")) -> Dict[str, Any]:
    dataset_dir = output_root / "dataset"
    log_dir = output_root / "logs"
    report_dir = output_root / "reports"
    scenario_dir = dataset_dir / "scenarios"

    for d in [scenario_dir, log_dir, report_dir]:
        d.mkdir(parents=True, exist_ok=True)

    # 1. Normal-flight dataset
    normal_data = NormalFlightSimulator(duration_s=duration, sample_period_s=0.1, seed=42).generate()
    save_jsonl(normal_data, dataset_dir / "normal_flight.jsonl")

    # 2. Attack scenario datasets
    for name, factory in SCENARIOS.items():
        save_jsonl(factory(42), scenario_dir / f"{name.lower()}.jsonl")

    # 3. Benchmarks & firmware demo
    benchmark = benchmark_all()
    firmware = run_firmware_demo(scenario_dir)

    # 4. Tamper-evident logging
    logger = HashChainedEventLogger(log_dir / "security_events.jsonl")
    for res in benchmark["results"]:
        logger.write({
            "event_type": "stage1_benchmark_result",
            "scenario": res["scenario"],
            "expected_attack": res["expected_attack"],
            "detected_attack": res["detected_attack"],
            "passed": res["passed"],
            "processing_latency_ms": res["processing_latency_ms"],
        })

    logger.write({
        "event_type": "firmware_integrity_test",
        "trusted_file_ok": firmware["trusted"]["integrity_ok"],
        "modified_file_mismatch_detected": firmware["mismatch_detected"],
    })

    # 5. Save report
    report = {
        "project": "Drone IDS Stage 1 Proof of Concept",
        "scope": "Controlled Python simulation",
        "benchmark": benchmark,
        "firmware_integrity": firmware,
        "note": (
            "Numerical thresholds are proposed Stage 1 PoC engineering "
            "values, not official competition thresholds."
        ),
    }
    save_report(report, report_dir / "stage1_benchmark.json")

    # Console display
    print()
    print("=" * 80)
    print("                 DRONE INTRUSION DETECTION SYSTEM - STAGE 1 PoC")
    print("=" * 80)
    print()
    print("SCENARIO EVALUATION RESULTS:")
    print("-" * 80)
    for res in benchmark["results"]:
        status = "PASS" if res["passed"] else "FAIL"
        print(
            f"{res['scenario']:<25} | {status:<4} | "
            f"Expected: {res['expected_attack']:<22} | "
            f"Detected: {res['detected_attack']:<22} | "
            f"{res['processing_latency_ms']:.4f} ms"
        )
    print("-" * 80)
    print(f"Attack Detection Rate : {benchmark['attack_detection_rate'] * 100:.2f}%")
    print(f"False Positive Rate   : {benchmark['false_positive_rate'] * 100:.2f}%")
    print(f"Average Latency       : {benchmark['average_processing_latency_ms']:.4f} ms")
    print(f"Attack Vectors Tested : {benchmark['attack_vector_coverage']}/{benchmark['attack_vector_total']}")
    print()
    print("FIRMWARE INTEGRITY VERIFICATION:")
    print("-" * 80)
    print(f"Trusted Firmware Check : {'PASS' if firmware['trusted']['integrity_ok'] else 'FAIL'}")
    print(f"Tamper Tamper Detection: {'CONFIRMED (Mismatch Caught)' if firmware['mismatch_detected'] else 'FAILED'}")
    print()
    print("ARTIFACTS GENERATED:")
    print("-" * 80)
    print(f"Datasets : {dataset_dir}")
    print(f"Logs     : {log_dir}")
    print(f"Reports  : {report_dir}")
    print("=" * 80)

    return report


# ============================================================
# 16. CLI
# ============================================================

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="PUSHPAK Objective 2 - Drone Intrusion Detection System (Stage 1 PoC)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=5.0,
        help="Duration of the normal-flight dataset in seconds.",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="stage1_output",
        help="Target output directory for logs, datasets, and reports.",
    )
    parser.add_argument(
        "--scenario",
        type=str,
        choices=list(SCENARIOS.keys()),
        help="Run a specific scenario instead of the full benchmark.",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run internal tests and exit.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return 0

    if args.scenario:
        print(f"Running individual scenario: {args.scenario}")
        res = run_scenario(args.scenario, SCENARIOS[args.scenario])
        status = "PASS" if res.passed else "FAIL"
        print(f"Result: {status} | Expected: {res.expected_attack} | Detected: {res.detected_attack} | Latency: {res.processing_latency_ms:.4f} ms")
        return 0 if res.passed else 1

    # Run self-tests first, then full demo
    self_test()
    run_stage1_demo(duration=args.duration, output_root=Path(args.output_dir))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
