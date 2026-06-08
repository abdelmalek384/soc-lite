from collections import defaultdict
import re
import csv

# Load logs
with open("logs.txt", "r") as file:
    logs = file.readlines()

# Data stores
failed_logins = defaultdict(list)   # store timestamps
port_scans = defaultdict(list)

ip_pattern = r"\d+\.\d+\.\d+\.\d+"
time_pattern = r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}"

alerts = []

# =========================
# ANALYSIS ENGINE
# =========================
for line in logs:
    line = line.strip()

    ip_match = re.findall(ip_pattern, line)
    time_match = re.findall(time_pattern, line)

    if not ip_match:
        continue

    ip = ip_match[0]
    timestamp = time_match[0] if time_match else "UNKNOWN"

    # Brute force tracking
    if "Failed login" in line:
        failed_logins[ip].append(timestamp)

    # Port scan tracking
    if "Port scan" in line:
        port_scans[ip].append(timestamp)

# =========================
# THREAT ENGINE
# =========================

# Brute force rule
for ip, times in failed_logins.items():
    if len(times) >= 3:
        alerts.append([
            "BRUTE FORCE ATTACK",
            ip,
            len(times),
            "HIGH"
        ])

# Port scan rule
for ip, times in port_scans.items():
    if len(times) >= 2:
        alerts.append([
            "PORT SCANNING",
            ip,
            len(times),
            "MEDIUM"
        ])

# =========================
# OUTPUT SECTION
# =========================

print("\n============================")
print("   SOC ANALYSIS REPORT")
print("============================\n")

for a in alerts:
    print(f"[{a[3]}] {a[0]}")
    print(f"IP: {a[1]}")
    print(f"Events: {a[2]}\n")

print("============================")
print(f"Total Alerts: {len(alerts)}")
print("============================\n")

# =========================
# EXPORT TO CSV (VERY IMPORTANT)
# =========================

with open("soc_alerts_report.csv", "w", newline="") as f:
    writer = csv.writer(f)

    writer.writerow(["Threat Type", "IP Address", "Event Count", "Severity"])

    for a in alerts:
        writer.writerow(a)

print("CSV report generated: soc_alerts_report.csv")