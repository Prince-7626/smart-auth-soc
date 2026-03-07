"""
Real-world log file generator with common attack patterns
Generates realistic auth logs, SSH logs, and web logs for the detection system to analyze
"""

import random
from datetime import datetime, timedelta
from pathlib import Path
import os

# Sample data
failed_users = ["admin", "root", "test", "guest", "user", "invalid", "unknown"]
suspicious_ips = [
    "192.168.1.100", "10.0.0.50", "172.16.0.25", "203.0.113.45",
    "198.51.100.23", "192.0.2.15", "203.0.113.99", "198.51.100.44"
]
legitimate_ips = ["192.168.1.50", "10.0.0.100", "172.16.1.200"]

sql_injection_payloads = [
    "' OR '1'='1",
    "1 UNION SELECT * FROM users",
    "'; DROP TABLE users; --",
    "1' AND '1'='1",
    "admin' --"
]

xss_payloads = [
    "<script>alert('xss')</script>",
    "<img src=x onerror='alert(1)'>",
    "javascript:alert('xss')",
    "<svg/onload=alert(1)>"
]

path_traversal_payloads = [
    "../../../etc/passwd",
    "../../..\\windows\\system32\\config\\sam",
    "..\\..\\..\\boot.ini",
    "....//....//....//etc/passwd"
]

def generate_auth_logs(count=20):
    """Generate realistic SSH/auth log entries"""
    logs = []
    
    for _ in range(count):
        ip = random.choice(suspicious_ips + legitimate_ips)
        user = random.choice(failed_users)
        timestamp = (datetime.now() - timedelta(hours=random.randint(0, 24))).strftime("%b %d %H:%M:%S")
        
        # Mix of authentication failures
        patterns = [
            f"{timestamp} localhost sshd[12345]: Failed password for {user} from {ip} port 22 ssh2",
            f"{timestamp} localhost sshd[12345]: Invalid user {user} from {ip} port 22",
            f"{timestamp} localhost sshd[12345]: authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={ip}",
            f"{timestamp} localhost auth: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={ip} user={user}",
            f"{timestamp} localhost sudo: {user}: command not allowed",
        ]
        
        logs.append(random.choice(patterns))
    
    return logs

def generate_http_logs(count=20):
    """Generate realistic HTTP access logs with attack payloads"""
    logs = []
    
    for _ in range(count):
        ip = random.choice(suspicious_ips + legitimate_ips)
        timestamp = (datetime.now() - timedelta(minutes=random.randint(0, 1440))).strftime("%d/%b/%Y:%H:%M:%S +0000")
        status = random.choice([200, 403, 404, 500]) if ip in suspicious_ips else 200
        bytes_sent = random.randint(100, 100000)
        
        # Different attack types
        attack_type = random.choice(['sql_injection', 'xss', 'path_traversal', 'normal'])
        
        if attack_type == 'sql_injection':
            payload = random.choice(sql_injection_payloads)
            path = f"/api/search?q={payload}"
            user_agent = "sqlmap/1.0"
        elif attack_type == 'xss':
            payload = random.choice(xss_payloads)
            path = f"/comment.php?text={payload}"
            user_agent = "Mozilla/5.0"
        elif attack_type == 'path_traversal':
            payload = random.choice(path_traversal_payloads)
            path = f"/download/{payload}"
            user_agent = "curl/7.68.0"
        else:
            path = random.choice(["/", "/index.php", "/api/users", "/dashboard", "/login"])
            user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        
        log = f'{ip} - - [{timestamp}] "GET {path} HTTP/1.1" {status} {bytes_sent} "-" "{user_agent}"'
        logs.append(log)
    
    return logs

def generate_firewall_logs(count=10):
    """Generate firewall/network logs"""
    logs = []
    ports = [22, 23, 3306, 5432, 27017, 6379, 9200, 445, 139, 135]
    
    for _ in range(count):
        ip = random.choice(suspicious_ips)
        port = random.choice(ports)
        timestamp = (datetime.now() - timedelta(hours=random.randint(0, 24))).strftime("%b %d %H:%M:%S")
        
        patterns = [
            f"{timestamp} [FIREWALL] Connection attempt blocked: {ip}:{port}",
            f"{timestamp} [IDS] Port scan detected from {ip}",
            f"{timestamp} [nsm] ALERT: Possible exploit attempt from {ip}:{port}",
        ]
        
        logs.append(random.choice(patterns))
    
    return logs

def save_sample_logs(filename="sample_logs/generated_logs.txt"):
    """Generate and save all log types to file"""
    Path("sample_logs").mkdir(exist_ok=True)
    
    all_logs = []
    all_logs.extend(generate_auth_logs(30))
    all_logs.extend(generate_http_logs(40))
    all_logs.extend(generate_firewall_logs(20))
    
    # Shuffle logs to simulate real-world order
    random.shuffle(all_logs)
    
    with open(filename, 'w') as f:
        f.write('\n'.join(all_logs))
    
    print(f"✓ Generated {len(all_logs)} sample logs in {filename}")
    return filename

if __name__ == "__main__":
    logfile = save_sample_logs()
    print(f"\nSample logs created at: {os.path.abspath(logfile)}")
    print("Feed these logs to /api/detection/analyze endpoint to test threat detection")
