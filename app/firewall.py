import subprocess
from datetime import datetime
import platform

blocked_ips = {}

def block_ip(ip, severity, location="Unknown"):
    """Block an IP address at the firewall level"""
    if ip in blocked_ips:
        return

    try:
        # Only attempt actual firewall blocking on Windows
        if platform.system() == "Windows":
            subprocess.run(
                [
                    "powershell",
                    "-Command",
                    f"New-NetFirewallRule -DisplayName 'Block_{ip}' "
                    f"-Direction Inbound -RemoteAddress {ip} -Action Block -ErrorAction SilentlyContinue"
                ],
                capture_output=True
            )

        blocked_ips[ip] = {
            "severity": severity,
            "blocked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "location": location,
            "reason": "Multiple failed login attempts (brute force detection)"
        }

        print(f"[MITIGATION] IP {ip} BLOCKED - Severity: {severity}")

    except Exception as e:
        print(f"[WARNING] Could not block IP {ip}: {e}")
        # Still record it even if firewall block fails
        blocked_ips[ip] = {
            "severity": severity,
            "blocked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "location": location,
            "reason": "Multiple failed login attempts (brute force detection)"
        }
