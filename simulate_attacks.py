import time
import datetime
import sys

LOG_FILE = "sample_logs/web_auth.log"
print(f"Generating attack logs to {LOG_FILE}...\n")

def write_log(ip, user, success=False):
    now = datetime.datetime.now()
    month = now.strftime("%b")
    day = now.strftime("%d")
    time_str = now.strftime("%H:%M:%S")
    status = "Accepted password for" if success else "Failed password for"
    
    log_line = f"{month} {day} {time_str} server sshd: {status} {user} from {ip}\n"
    with open(LOG_FILE, "a") as f:
        f.write(log_line)
    sys.stdout.write(f"Generated: {log_line}")
    sys.stdout.flush()

try:
    # 1. Simulate Brute Force
    ip1 = "45.132.18.2" 
    print("--- Simulating Brute Force Attack ---")
    for i in range(6):
        write_log(ip1, "admin")
        time.sleep(0.5)
        
    time.sleep(2)
    
    # 2. Simulate UEBA Anomaly (Success from strange IP)
    print("\n--- Simulating UEBA Anomaly ---")
    strange_ip = "185.15.54.120"
    write_log(strange_ip, "analyst", success=True)
    
    time.sleep(2)
    
    # 3. Simulate another brute force attack
    ip2 = "104.24.12.5"
    print("\n--- Simulating Second Brute Force Attack ---")
    for i in range(8):
        write_log(ip2, "root")
        time.sleep(0.3)
        
    print("\nSimulation complete! Check your dashboard.")
except KeyboardInterrupt:
    print("\nStopped.")
