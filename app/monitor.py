import time
import re
import json
import os
from datetime import datetime, timedelta
from colorama import Fore, init
from collections import defaultdict

from app.config import TIME_WINDOW, ATTEMPT_THRESHOLD, LOG_FILE_PATH
from app.analytics import ip_activity
from app.firewall import block_ip, blocked_ips
from app.ml_engine import detect_anomaly
from app.geoip import lookup

init(autoreset=True)

# Global counters
total_failed_attempts = 0
ml_anomalies = 0
ml_anomaly_list = []

# Log pattern for parsing auth logs
LOG_PATTERN = re.compile(
    r'(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+).*'
    r'Failed password for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)'
)

def get_severity(count):
    """Determine severity based on failed attempt count"""
    if count >= 8:
        return "CRITICAL"
    elif count >= 5:
        return "HIGH"
    else:
        return "MEDIUM"

def update_soc_data():
    """Update the soc_data.json file with current metrics"""
    global total_failed_attempts, ml_anomalies, blocked_ips
    
    # Use absolute path for soc_data.json
    soc_data_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "soc_data.json")
    
    data = {
        "total_failed": total_failed_attempts,
        "unique_ips": len(ip_activity),
        "blocked_ips": blocked_ips,
        "ml_alerts": len(ml_anomaly_list)
    }

    try:
        with open(soc_data_path, "w") as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        print(Fore.RED + f"[ERROR] Could not update soc_data.json: {e}")

def monitor():
    """Main monitoring loop - watches log file for failed login attempts"""
    global total_failed_attempts, ml_anomalies, ml_anomaly_list
    
    print(Fore.CYAN + "\n" + "="*70)
    print("SMART AUTHENTICATION SOC PLATFORM - MONITORING MODE".center(70))
    print("="*70)
    print(Fore.CYAN + f"Watching: {LOG_FILE_PATH}")
    print(f"Time Window: {TIME_WINDOW}s | Threshold: {ATTEMPT_THRESHOLD} attempts\n")

    try:
        with open(LOG_FILE_PATH, "r", encoding="utf-8", errors="ignore") as file:
            # Start at end of file
            file.seek(0, 2)
            last_update = time.time()

            while True:
                line = file.readline()
                
                if not line:
                    # Update data every 5 seconds even if no new logs
                    if time.time() - last_update > 5:
                        update_soc_data()
                        last_update = time.time()
                    time.sleep(0.5)
                    continue

                match = LOG_PATTERN.search(line)
                if match:
                    timestamp = datetime.now()
                    ip = match.group("ip")
                    user = match.group("user")

                    # Increment failed attempts
                    total_failed_attempts += 1
                    ip_activity[ip].append(timestamp)

                    # Keep only attempts within time window
                    window_start = timestamp - timedelta(seconds=TIME_WINDOW)
                    ip_activity[ip] = [t for t in ip_activity[ip] if t >= window_start]

                    count = len(ip_activity[ip])

                    print(Fore.GREEN + f"[INFO] Failed login: {user}@{ip} (Count: {count})")

                    # Check if threshold exceeded
                    if count >= ATTEMPT_THRESHOLD:
                        severity = get_severity(count)
                        print(Fore.RED + f"[{severity}] BRUTE FORCE DETECTED from {ip}")

                        # Get geo information
                        geo = lookup(ip)
                        if geo:
                            location = f"{geo.get('city', 'N/A')}, {geo.get('country', 'N/A')}"
                            print(Fore.YELLOW + f"📍 Location: {location} | ISP: {geo.get('isp', 'N/A')}")
                        else:
                            location = "Unknown"

                        # Block IP
                        block_ip(ip, severity)
                        
                        # Update blocked IPs with location
                        if ip in blocked_ips:
                            blocked_ips[ip]['location'] = location

                        # Check for anomalies
                        if detect_anomaly(ip, count):
                            ml_anomalies += 1
                            ml_anomaly_list.append(ip)
                            print(Fore.MAGENTA + f"[ML] 🤖 ANOMALY DETECTED from {ip}")

                    # Update data every 5 seconds
                    if time.time() - last_update > 5:
                        update_soc_data()
                        last_update = time.time()

    except KeyboardInterrupt:
        print(Fore.CYAN + "\n\n⏹️  Monitoring stopped by user")
        update_soc_data()
    except FileNotFoundError:
        print(Fore.RED + f"[ERROR] Log file not found: {LOG_FILE_PATH}")
        print(Fore.YELLOW + "        Create auth logs in sample_logs/web_auth.log first")
    except Exception as e:
        print(Fore.RED + f"[ERROR] {e}")
        update_soc_data()
