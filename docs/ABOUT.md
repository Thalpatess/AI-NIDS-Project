# About AI-NIDS-Project

AI-NIDS-Project is a practical, enterprise-oriented prototype for passive network intrusion detection. The project demonstrates how mirrored network traffic can be processed by a dedicated monitoring appliance to detect suspicious behavioral patterns without interfering with the production data plane.

## Mission

The project focuses on building a realistic AI-assisted NIDS workflow that mirrors common enterprise security operations:

- traffic capture through network port mirroring (SPAN)
- flow-level telemetry extraction from mirrored packets
- anomaly scoring using baseline-driven behavior analysis
- alert generation and classification for SOC workflows
- metrics and dashboards for visualization and monitoring

## Architectural intent

The design reflects a typical enterprise deployment model:

- Production network traffic remains on the normal forwarding path
- A core switch mirrors traffic to a dedicated NIDS interface
- The monitoring appliance does not speak on the production network except for egress to monitoring systems
- Event or alert data is forwarded to SIEM, SOC tooling, or dashboards for response and triage

This ensures the detection system remains passive, non-disruptive, and aligned with security best practices.

## Why this project matters

Network security teams often need a simple but realistic way to prototype AI-assisted traffic inspection without deploying a full commercial platform. This repository provides a reference architecture for:

- understanding mirrored traffic capture
- building network telemetry features
- engineering anomaly detection logic
- exposing detection results through APIs and dashboards
- establishing a baseline for enterprise deployment hardening

## Use cases

- detection of reconnaissance activity
- abnormal data transfer patterns
- suspicious high-rate traffic conditions
- correlation of telemetry with SOC workflows
- baseline-driven anomaly scoring for internal networks

## Security posture

The project is explicitly designed around receive-only monitoring, network isolation, and conservative egress behavior. These constraints are central to the architecture so the NIDS appliance does not become an attack surface or a path for traffic injection.

This repository is intended as an educational and enterprise-prototype reference, not a replacement for a hardened production NIDS platform.
