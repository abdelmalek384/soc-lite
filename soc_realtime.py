import time
from collections import defaultdict
import re

log_file = "logs.txt"

failed_logins = defaultdict(int)
port_scans = defaultdict(int)

ip_pattern = r"\d+\.\d+\.\d+\.\d+"

print("\n[+] SOC REAL-TIME MONITORING STARTED...\n")

# Track file size (for new logs only)
with open(log_file, "r") as f:
    f.seek(0, 2)  # move to end

    while True:
        line = f.readline()

        if not line:
            time.sleep(1)
            continue

        line = line.strip()

        ip = re.findall(ip_pattern, line)
        if not ip:
            continue

        ip = ip[0]

        # Detection logic
        if "Failed login" in line:
            failed_logins[ip] += 1

            if failed_logins[ip] == 3:
                print(f"[ALERT - HIGH] Brute Force Detected from {ip}")

        if "Port scan" in line:
            port_scans[ip] += 1

            if port_scans[ip] == 2:
                print(f"[ALERT - MEDIUM] Port Scan Detected from {ip}")