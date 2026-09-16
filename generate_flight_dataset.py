#!/usr/bin/env python3
"""
Large-Scale Real-Life Drone Flight Dataset Generator
PUSHPAK Grand Challenge 2026 - Techfest, IIT Bombay

Generates a high-fidelity multi-waypoint flight path (>10 km) centered around
IIT Bombay & Powai Lake, Mumbai (19.1330° N, 72.9150° E).

Key Features:
- Realistic aerodynamics: bank angles, wind gusts, atmospheric turbulence
- GPS constellation noise (HDOP variations, satellite count changes)
- Barometric altitude drift vs. GPS altitude
- Realistic battery drain physics (4S LiPo: 16.8V -> 14.9V)
- Interleaved attack injection across 6 diverse threat vectors
- Covers >10 km total distance across thousands of 10 Hz telemetry frames
"""

from __future__ import annotations

import argparse
import json
import math
import random
from dataclasses import asdict
from pathlib import Path
from typing import List, Tuple

# Import data model from main IDS engine
from stage1_drone_ids import DroneTelemetry, haversine_m


# Waypoints around IIT Bombay campus and Powai Lake (Lat, Lon, Target Alt)
IIT_BOMBAY_WAYPOINTS: List[Tuple[float, float, float]] = [
    (19.1334, 72.9133, 40.0),  # Main Gate / SAC
    (19.1350, 72.9050, 55.0),  # Powai Lake West Bank
    (19.1280, 72.9020, 60.0),  # Hiranandani Shoreline
    (19.1220, 72.9100, 50.0),  # Powai South
    (19.1260, 72.9200, 45.0),  # Kanjurmarg Perimeter
    (19.1340, 72.9240, 65.0),  # Hillside Woods
    (19.1410, 72.9180, 70.0),  # Vihar Lake Approach
    (19.1380, 72.9120, 45.0),  # Gymkhana Grounds
]


def generate_large_flight_dataset(
    output_path: Path,
    target_distance_km: float = 10.0,
    sample_rate_hz: float = 10.0,
    seed: int = 42,
) -> int:
    rng = random.Random(seed)
    dt = 1.0 / sample_rate_hz

    # Start at IIT Bombay Main Gate
    curr_lat, curr_lon, curr_alt = IIT_BOMBAY_WAYPOINTS[0]
    curr_heading = 45.0
    ground_speed = 10.0  # m/s (36 km/h)
    battery_v = 16.8

    total_dist_m = 0.0
    target_dist_m = target_distance_km * 1000.0

    records: List[DroneTelemetry] = []
    waypoint_idx = 1
    t = 0.0
    command_counter = 0

    # Plan attack injection segments (frame start and duration)
    # We will inject 6 realistic attack phases spread across the flight
    attack_schedule = [
        # (Start frame, duration, attack_type)
        (1500, 80, "GPS_SPOOFING"),
        (3000, 90, "MAVLINK_ANOMALY"),
        (4500, 70, "COMMAND_ANOMALY"),
        (6000, 85, "TELEMETRY_MANIPULATION"),
        (7500, 90, "DOS_ANOMALY"),
        (9000, 80, "REPLAY_ATTACK"),
    ]

    print(f"[*] Simulating realistic {target_distance_km:.1f} km flight path around IIT Bombay...")

    frame = 0
    replay_buffer: List[DroneTelemetry] = []

    while total_dist_m < target_dist_m or frame < 9500:
        target_lat, target_lon, target_alt = IIT_BOMBAY_WAYPOINTS[waypoint_idx]

        # Calculate bearing to target waypoint
        d_lat = target_lat - curr_lat
        d_lon = target_lon - curr_lon
        target_heading = math.degrees(math.atan2(d_lon, d_lat)) % 360.0

        # Smooth turn toward waypoint (max 15 deg/sec)
        heading_err = (target_heading - curr_heading + 180.0) % 360.0 - 180.0
        turn_rate = max(-15.0 * dt, min(15.0 * dt, heading_err))
        curr_heading = (curr_heading + turn_rate) % 360.0

        # Smooth altitude adjustment
        alt_err = target_alt - curr_alt
        curr_alt += max(-2.5 * dt, min(2.5 * dt, alt_err))

        # Speed with natural aerodynamic wind turbulence
        wind_gust = 0.35 * math.sin(t / 2.5) + rng.uniform(-0.15, 0.15)
        current_speed = max(6.0, min(16.0, ground_speed + wind_gust))

        # Update position
        dist_step = current_speed * dt
        north_m = dist_step * math.cos(math.radians(curr_heading))
        east_m = dist_step * math.sin(math.radians(curr_heading))

        next_lat = curr_lat + (north_m / 111_320.0)
        next_lon = curr_lon + (east_m / (111_320.0 * max(math.cos(math.radians(curr_lat)), 0.2)))

        step_actual_dist = haversine_m(curr_lat, curr_lon, next_lat, next_lon)
        total_dist_m += step_actual_dist
        curr_lat, curr_lon = next_lat, next_lon

        # Cycle waypoints if reached (< 50m)
        dist_to_wp = haversine_m(curr_lat, curr_lon, target_lat, target_lon)
        if dist_to_wp < 50.0:
            waypoint_idx = (waypoint_idx + 1) % len(IIT_BOMBAY_WAYPOINTS)

        # Realistic sensor characteristics
        gps_speed = current_speed + rng.uniform(-0.12, 0.12)
        hdop = max(0.6, 0.85 + 0.1 * math.sin(t / 10.0) + rng.uniform(-0.05, 0.05))
        satellites = int(14 + rng.choice([-1, 0, 0, 0, 1]))
        roll = max(-18.0, min(18.0, 3.5 * turn_rate / dt + rng.uniform(-0.4, 0.4)))
        pitch = max(-12.0, min(12.0, 1.8 * math.sin(t / 3.0) + rng.uniform(-0.3, 0.3)))
        battery_v = max(14.6, 16.8 - (0.00018 * t))
        message_rate = 10.0 + rng.uniform(-0.4, 0.4)

        if frame % 15 == 0:
            command_counter += 1

        # Check for scheduled attacks
        active_attack = "NONE"
        scenario_name = "NORMAL_CRUISE"

        for start_f, duration, atk_type in attack_schedule:
            if start_f <= frame < start_f + duration:
                active_attack = atk_type
                scenario_name = atk_type
                break

        # Construct frame
        item = DroneTelemetry(
            timestamp=round(t, 2),
            latitude=curr_lat,
            longitude=curr_lon,
            gps_speed=gps_speed,
            ground_speed=current_speed,
            altitude=curr_alt + rng.uniform(-0.1, 0.1),
            heading=round(curr_heading, 2),
            satellites=satellites,
            hdop=round(hdop, 2),
            roll=round(roll, 2),
            pitch=round(pitch, 2),
            battery_voltage=round(battery_v, 2),
            flight_mode="AUTO",
            message_type="GLOBAL_POSITION_INT",
            message_rate=round(message_rate, 2),
            command_count=command_counter,
            baro_altitude=round(curr_alt + rng.uniform(-0.2, 0.2), 2),
            scenario=scenario_name,
            expected_attack=active_attack,
        )

        # Inject attack modifications
        if active_attack == "GPS_SPOOFING":
            # Doppler velocity discordance (>18 m/s delta)
            item.gps_speed = current_speed + 32.0
            item.satellites = 6
            item.hdop = 2.4

        elif active_attack == "MAVLINK_ANOMALY":
            # Telemetry rate surge
            item.message_rate = 52.0

        elif active_attack == "COMMAND_ANOMALY":
            # Command flooding
            item.command_count += 35 * (frame - 4500 + 1)

        elif active_attack == "TELEMETRY_MANIPULATION":
            # Baro vs GPS altitude manipulation (delta > 30m)
            item.altitude = curr_alt + 38.0
            item.baro_altitude = curr_alt

        elif active_attack == "DOS_ANOMALY":
            # Extreme denial-of-service packet storm
            item.message_rate = 115.0

        elif active_attack == "REPLAY_ATTACK":
            # Frozen telemetry playback: attacker replays frozen position while drone is cruising
            if not replay_buffer:
                replay_buffer = [records[-1]]
            stale_sample = replay_buffer[0]
            item.latitude = stale_sample.latitude
            item.longitude = stale_sample.longitude
            item.altitude = stale_sample.altitude
            item.gps_speed = stale_sample.gps_speed

        records.append(item)
        t += dt
        frame += 1

    # Save to JSONL
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        for r in records:
            handle.write(json.dumps(asdict(r), separators=(",", ":")) + "\n")

    print(f"[+] Successfully generated {len(records):,} telemetry frames.")
    print(f"[+] Total distance covered : {total_dist_m / 1000.0:.2f} km")
    print(f"[+] Flight time simulated  : {t / 60.0:.1f} minutes")
    print(f"[+] Saved dataset file to  : {output_path}")
    return len(records)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate Large-Scale Drone Telemetry Dataset")
    parser.add_argument("--distance", type=float, default=10.5, help="Target trajectory distance in km")
    parser.add_argument("--output", type=str, default="dataset/large_real_life_flight.jsonl", help="Output JSONL path")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility")
    args = parser.parse_args()

    generate_large_flight_dataset(
        output_path=Path(args.output),
        target_distance_km=args.distance,
        seed=args.seed,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
