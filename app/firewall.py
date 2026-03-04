import subprocess
from datetime import datetime

blocked_ips = {}

def block_ip(ip, severity):
    if ip in blocked_ips:
        return

    try:
        subprocess.run(
            [
                "powershell",
                "-Command",
                f"New-NetFirewallRule -DisplayName 'Block_{ip}' "
                f"-Direction Inbound -RemoteAddress {ip} -Action Block"
            ],
            capture_output=True
        )

        blocked_ips[ip] = {
            "severity": severity,
            "blocked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        print(f"[MITIGATION] IP {ip} BLOCKED successfully.")

    except Exception as e:
        print("Firewall block failed:", e)
