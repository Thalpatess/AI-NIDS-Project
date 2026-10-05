# Security Hardening and Deployment Best Practices

## Network Configuration

### 1. SPAN Port Configuration (Cisco IOS-XE)

```bash
# Enter global configuration mode
config terminal

# Define SPAN session with receive-only capability
monitor session 1 source vlan 10, 20, 30
monitor session 1 destination interface GigabitEthernet0/1

# Disable source learning on destination port (receive-only)
no monitor session 1 destination ingress

# Apply ingress traffic filtering to prevent injection
interface GigabitEthernet0/1
  description NIDS-Mirror-Port
  no switchport
  no ip address
  shutdown
exit

# Disable packet forwarding on NIDS interface
no ip forwarding

exit
```

### 2. NIDS Appliance Network Isolation

```bash
# Isolate management interface
interface GigabitEthernet0/2
  description NIDS-Management
  ip address 192.168.50.100 255.255.255.0
  ip access-group NIDS-MGMT-ACL in
exit

# ACL: Restrict management to secure subnets only
ip access-list extended NIDS-MGMT-ACL
  permit tcp 10.0.1.0 0.0.0.255 any eq 8080  # API calls from SOC
  permit tcp 10.0.1.0 0.0.0.255 any eq 3000  # Grafana dashboard
  permit tcp 10.0.1.0 0.0.0.255 any eq 9090  # Prometheus
  permit tcp 10.0.2.0 0.0.0.255 any eq 514   # Syslog to SIEM
  deny ip any any log
exit
```

## Container Security

### Docker Security Hardening

```dockerfile
# Run as non-root user
RUN addgroup -S nids && adduser -S nids -G nids
USER nids

# Read-only filesystem except for volatile directories
RUN chmod 0755 /app
RUN mkdir -p /tmp /var/run /var/log/nids
RUN chown -R nids:nids /tmp /var/run /var/log/nids

# Drop unnecessary capabilities
CAPABILITIES: drop=all,add=NET_ADMIN,NET_RAW,SYS_ADMIN

# Disable privileged mode (only use when necessary for packet capture)
SECURITY_OPT: no-new-privileges:true
```

### Docker Compose Security Config

```yaml
services:
  nids:
    cap_add:
      - NET_ADMIN
      - NET_RAW
    cap_drop:
      - ALL
    read_only: true
    tmpfs:
      - /tmp
      - /var/run
    volumes:
      - /var/log/nids:rw
    security_opt:
      - no-new-privileges:true
    user: "1000:1000"
```

## Traffic Analysis Best Practices

### 1. Feature Engineering for ML Model

**Flow-Level Features:**
- Flow duration (seconds)
- Packet rate (packets/sec)
- Byte rate (bytes/sec)
- Total packet count
- Forward/backward payload entropy
- TCP flag frequencies (SYN, ACK, RST, FIN)
- Inter-arrival time mean
- Idle time maximum
- Flow size (total bytes)

**Baseline Establishment (14-day ingestion):**
- Week 1: Collect normal traffic patterns
- Week 2: Establish statistical baselines for each flow type
- Calculate mean, std dev, min/max for all features
- Define anomaly thresholds (e.g., 3-sigma deviation)

### 2. False Positive Mitigation

**Whitelisting Strategies:**
```python
WHITELIST = {
    "dns_queries": {
        "dst_port": 53,
        "packet_rate_threshold": 1000,
        "allowed_dst_ips": ["8.8.8.8", "1.1.1.1"]
    },
    "ntp_sync": {
        "dst_port": 123,
        "allowed_packet_rate": 50,
        "allowed_dst_ips": ["pool.ntp.org"]
    },
    "backups": {
        "dst_port": 9102,
        "allowed_byte_rate": 100000000,
        "allowed_src_ips": ["10.0.2.0/24"]
    }
}
```

### 3. Alert Handling

**Alert Routing:**
```json
{
  "alert_rules": [
    {
      "type": "port_scan",
      "classification": "reconnaissance",
      "severity": "high",
      "action": "forward_to_siem",
      "escalation": "soc_oncall"
    },
    {
      "type": "data_exfiltration",
      "classification": "data_theft",
      "severity": "critical",
      "action": ["forward_to_siem", "block_flow", "page_security_team"]
    }
  ]
}
```

## SIEM Integration

### CEF (Common Event Format) Export

```json
{
  "CEF:0|ThalpatessNIDS|AI-NIDS|1.0|port_scan|Port Scan Detected|8|
  src=192.168.1.100 spt=54321 dst=10.0.0.8 dpt=443 proto=tcp 
  cs1Label=alert_id cs1=alert-001 cs2Label=anomaly_score cs2=88.5
  cs3Label=classification cs3=reconnaissance"
}
```

### Splunk Integration

```
[nids]
index = security
sourcetype = nids:alert
source = /var/log/nids/alerts.json
host = nids-appliance-01
token = {SPLUNK_HEC_TOKEN}
endpoint = https://splunk-hec.internal:8088/services/collector
```

## Deployment Checklist

- [ ] SPAN port configured as receive-only, no injection possible
- [ ] NIDS interface has no IP address (isolated from routing)
- [ ] Outbound traffic restricted to SIEM/monitoring endpoints
- [ ] NTP synchronized with secure stratum-2 server
- [ ] Packet capture ring buffer tuned for load
- [ ] ML model trained on 2+ weeks of environment baseline
- [ ] Alert thresholds calibrated to <5% false positive rate
- [ ] SIEM integration tested with sample alerts
- [ ] Logs encrypted in transit (TLS 1.2+)
- [ ] API authentication enabled (mTLS or API keys)
- [ ] Container image scanned for CVEs
- [ ] Resource limits set (CPU, memory)
- [ ] Health checks configured with alerting
