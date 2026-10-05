# AI-NIDS-Project

An enterprise-ready AI-powered Network Intrusion Detection System (NIDS) prototype built with:
- Go for high-performance packet capture and flow analysis
- Python for ML feature engineering and anomaly scoring
- Prometheus + Grafana for real-time monitoring and dashboarding
- Docker Compose for local deployment

The project is designed to demonstrate an end-to-end architecture for passive network traffic inspection using SPAN/mirror traffic, feature extraction, and AI-assisted anomaly detection.

## About the project

AI-NIDS-Project is a security-focused prototype designed to showcase how mirrored network traffic can be ingested, analyzed, and scored in real time for anomalous behavior. The system is intentionally built around the enterprise pattern of a passive monitoring architecture:

- Production traffic is mirrored through a switch SPAN port
- A dedicated appliance receives the copy without participating in routing
- Packet and flow telemetry are extracted for behavioral analysis
- ML models rank suspicious sessions or connections against learned baselines
- Detection outcomes are exposed through Prometheus metrics and Grafana dashboards
- Security alerts are formatted for downstream SIEM or SOC workflows

This repository is meant to be a practical reference for:
- passive network monitoring in enterprise networks
- anomaly-based IDS development
- flow intelligence and detection feature engineering
- alerting pipelines for SOC operations
- operational visualization of NIDS telemetry

## Features
- Passive packet capture from a mirrored interface
- Flow-level telemetry aggregation
- Protocol and payload feature extraction
- Anomaly detection pipeline using isolation forest / supervised ML pattern
- Metrics export for Prometheus
- Grafana dashboard for security telemetry
- Dockerized deployment

## Project structure
- `cmd/nids` — capture and monitoring entrypoint
- `internal` — packet parsing and metrics logic
- `python` — ML training and model service
- `dashboard` — Prometheus and Grafana configuration
- `docker-compose.yml` — local stack bootstrapping

## Quick start

### 1. Start the full stack

```bash
docker compose up --build
```

### 2. Access the dashboard
- Grafana: http://localhost:3000
- Prometheus: http://localhost:9090

### 3. Train the model

```bash
cd python
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python train_model.py
```

### 4. Run the packet capture service directly

```bash
go run ./cmd/nids --iface eth0
```

## Notes
- For production deployment, mirror traffic should be received on a dedicated interface with no egress capability.
- The NIDS appliance should be deployed on an isolated management network and hardened per enterprise security standards.
- This repository is a reference implementation and should be adapted to your environment and data sources.

## Security expectations
- Interface should be receive-only
- No IP forwarding
- No routing between management and production networks
- Restrict egress to SIEM and monitoring endpoints only

## License
This project is provided for educational and enterprise prototyping purposes.
