import time
import re
from datetime import datetime, timedelta
from colorama import Fore, init

from app.config import TIME_WINDOW, ATTEMPT_THRESHOLD, LOG_FILE_PATH
from app.analytics import ip_activity, increment_failed, increment_ml
from app.firewall import block_ip, blocked_ips
from app.ml_engine import detect_anomaly
from app.geoip import lookup

init(autoreset=True)

LOG_PATTERN = re.compile(
    r'(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+).*'
    r'Failed password for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)'
)

def get_severity(count):
    if count >= 8:
        return "CRITICAL"
    elif count >= 5:
        return "HIGH"
    else:
        return "MEDIUM"

def monitor():
    print(Fore.CYAN + "\nSMART AUTHENTICATION SOC PLATFORM STARTED\n")

    with open(LOG_FILE_PATH, "r", encoding="utf-8", errors="ignore") as file:
        file.seek(0, 2)

        while True:
            line = file.readline()
            if not line:
                time.sleep(1)
                continue

            match = LOG_PATTERN.search(line)
            if match:
                timestamp = datetime.now()
                ip = match.group("ip")
                user = match.group("user")

                increment_failed()
                ip_activity[ip].append(timestamp)

                window_start = timestamp - timedelta(seconds=TIME_WINDOW)
                ip_activity[ip] = [t for t in ip_activity[ip] if t >= window_start]

                count = len(ip_activity[ip])

                print(Fore.GREEN + f"[INFO] Failed login from {ip} -> User: {user}")

                if count >= ATTEMPT_THRESHOLD:
                    severity = get_severity(count)

                    print(Fore.RED + f"[{severity}] Brute Force Detected from {ip}")

                    geo = lookup(ip)
                    if geo:
                        print(Fore.YELLOW + f"Country: {geo['country']} | City: {geo['city']} | ISP: {geo['isp']}")

                    block_ip(ip, severity)

                if detect_anomaly(ip, count):
                    increment_ml()
                    print(Fore.MAGENTA + f"[ML] Anomaly detected from {ip}")
