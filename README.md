# Drone Intrusion Detection System (Drone-IDS)

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Dependencies: None](https://img.shields.io/badge/dependencies-standard--lib-green.svg)](https://docs.python.org/3/library/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> **PUSHPAK Grand Challenge 2026** — Grand Challenge 3: Security of Drones | Objective 2: Drone Intrusion Detection System (Stage 1 Proof-of-Concept)

A lightweight, high-performance, multi-vector Drone Intrusion Detection System (IDS) implemented entirely with the Python Standard Library (**zero external dependencies**). It models drone physics, extracts kinematic and communication features in real-time, detects anomalies, verifies firmware integrity, and maintains cryptographic tamper-evident audit logs.

---

## 🚀 Key Features

- **Kinematic & Sensor Consistency**:
  - Great-circle distance calculations via the Haversine formula.
  - Heading angle-wrap difference resolution.
  - GPS vs. inertial ground-speed discordance analysis.
  - Altitude change and physical climb-rate anomaly detection.
  - GPS fix quality scoring based on satellite count and HDOP.
- **Multi-Vector Threat Detection**:
  - **GPS Spoofing**: Detects sudden divergence between GPS Doppler speed and inertial navigation sensors.
  - **MAVLink Anomaly**: Catches protocol-level rate surges and message flooding.
  - **Command Injection / Anomaly**: Flags unauthorized command rates and flight mode manipulation.
  - **Telemetry Manipulation**: Discovers spoofed coordinate offsets and sensor disagreements.
  - **Denial of Service (DoS)**: Recognizes extreme packet ingestion rates designed to exhaust autopilot compute.
- **Cryptographic Security**:
  - **Firmware Verification**: Chunked SHA-256 integrity checks against trusted firmware baseline digests.
  - **Tamper-Evident Hash-Chained Audit Logs**: Every security alert is hashed and linked to the prior record's SHA-256 digest (`previous_hash -> record_hash`), guaranteeing audit trail immutability.
- **Zero-Dependency & Blazing Fast**:
  - Written in pure Python 3.10+ (sub-millisecond evaluation latency per telemetry frame, typically < 0.01 ms).

---

## 📁 Repository Structure

```text
├── stage1_drone_ids.py       # Complete single-file IDS & simulation engine
├── README.md                 # Project documentation & benchmark overview
├── requirements.txt          # Dependencies (standard library only)
├── .gitignore                # Excludes runtime outputs and cache files
├── .github/
│   └── workflows/
│       └── test.yml          # Automated CI workflow
└── stage1_output/            # (Generated at runtime)
    ├── dataset/              # Normal-flight & attack scenario JSONL streams
    ├── logs/                 # Cryptographically hash-chained event logs
    └── reports/              # JSON benchmark reports & accuracy metrics
```

---

## 🛠️ Quickstart

### Prerequisites
- Python 3.10 or higher.
- No external packages (`pip`) required.

### 1. Run Internal Self-Tests
Verify that all detectors, feature extractors, and cryptographic utilities operate correctly:
```bash
python stage1_drone_ids.py --self-test
```

### 2. Run the Full Benchmark & Simulation Demo
Simulates normal flight, executes all 5 attack scenarios, validates firmware, and generates reports:
```bash
python stage1_drone_ids.py
```

### 3. Test a Specific Threat Vector
Inspect an isolated attack vector:
```bash
python stage1_drone_ids.py --scenario GPS_SPOOFING
```
Available scenarios: `NORMAL`, `GPS_SPOOFING`, `MAVLINK_ANOMALY`, `COMMAND_ANOMALY`, `TELEMETRY_MANIPULATION`, `DOS_ANOMALY`.

### 4. Custom Output Directory and Flight Duration
```bash
python stage1_drone_ids.py --duration 10.0 --output-dir my_results
```

---

## 📊 Benchmark Results

Running `python stage1_drone_ids.py` evaluates all scenarios and generates an audit report:

```text
================================================================================
                 DRONE INTRUSION DETECTION SYSTEM - STAGE 1 PoC
================================================================================

SCENARIO EVALUATION RESULTS:
--------------------------------------------------------------------------------
NORMAL                    | PASS | Expected: NONE                   | Detected: NONE                   | 0.0031 ms
GPS_SPOOFING              | PASS | Expected: GPS_SPOOFING           | Detected: GPS_SPOOFING           | 0.0071 ms
MAVLINK_ANOMALY           | PASS | Expected: MAVLINK_ANOMALY        | Detected: MAVLINK_ANOMALY        | 0.0038 ms
COMMAND_ANOMALY           | PASS | Expected: COMMAND_ANOMALY        | Detected: COMMAND_ANOMALY        | 0.0035 ms
TELEMETRY_MANIPULATION    | PASS | Expected: TELEMETRY_MANIPULATION | Detected: TELEMETRY_MANIPULATION | 0.0038 ms
DOS_ANOMALY               | PASS | Expected: DOS_ANOMALY            | Detected: DOS_ANOMALY            | 0.0038 ms
--------------------------------------------------------------------------------
Attack Detection Rate : 100.00%
False Positive Rate   : 0.00%
Average Latency       : 0.0042 ms
Attack Vectors Tested : 5/5

FIRMWARE INTEGRITY VERIFICATION:
--------------------------------------------------------------------------------
Trusted Firmware Check : PASS
Tamper Detection       : CONFIRMED (Mismatch Caught)
================================================================================
```

---

## 🛡️ Architecture Overview

```
[ Telemetry Stream ]
       │
       ▼
[ FeatureEngine ] ──▶ (kinematics, delta distance, angles, rates, GPS quality)
       │
       ▼
[ DetectionEngine ] ──▶ [ GPSDetector ]
                    ──▶ [ MAVLinkDetector ]
                    ──▶ [ CommandDetector ]
                    ──▶ [ TelemetryConsistencyDetector ]
                    ──▶ [ DOSDetector ]
       │
       ▼
[ SecurityAlerts ] ──▶ [ HashChainedEventLogger ] ──▶ (Immutable SHA-256 Audit Log)
```

---

## 📜 License
This project is licensed under the MIT License.
