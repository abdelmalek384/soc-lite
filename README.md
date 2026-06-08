# SOC-Lite: Network Security Monitoring & Threat Detection Lab

## Overview
SOC-Lite is a cybersecurity simulation project that demonstrates real-world SOC (Security Operations Center) monitoring concepts using Python-based log analysis, attack detection, and security reporting.

The system simulates brute-force attacks, port scanning activity, and generates structured security alerts similar to SIEM platforms.

---

## Features

- Real-time log monitoring simulation
- Brute-force attack detection
- Port scanning detection
- IP-based correlation analysis
- Severity-based alert classification (LOW / MEDIUM / HIGH)
- CSV report generation for incident tracking
- Basic SOC dashboard visualization

---

## Architecture

The system simulates a real SOC workflow:

Attacker (Kali Linux)
        ↓
Network Logs (Firewall / Linux / System)
        ↓
Python Log Analyzer (Detection Engine)
        ↓
Alert Generation System
        ↓
CSV Report / Dashboard Output

---

## Technologies Used

- Python 3
- Regex (log parsing)
- File handling
- Matplotlib (visualization)
- CSV reporting

---

## Security Concepts Covered

- Brute-force detection
- Network scanning detection
- Log correlation
- Threat classification
- SOC workflow simulation

---

## How to Run

```bash
cd SOC-Lite/src
python3 log_analyzer.py
