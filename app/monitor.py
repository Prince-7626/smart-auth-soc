import time
import re
import json
import os
from datetime import datetime, timedelta
from app.database import db, BlockedIP, Incident, SecurityMetric
from colorama import Fore, init
from collections import defaultdict

from app.config import TIME_WINDOW, ATTEMPT_THRESHOLD, LOG_FILE_PATH
from app.analytics import ip_activity
from app.firewall import block_ip, blocked_ips
from app.ml_engine import AnomalyDetector, detect_anomaly
from app.geoip import lookup
from app.threat_intel import ThreatIntelAPI
from app.soar import AutomatedResponse

init(autoreset=True)

# Global counters
total_failed_attempts = 0
ml_anomalies = 0
ml_anomaly_list = []

# Log pattern for parsing auth logs
FAILED_LOG_PATTERN = re.compile(
    r'(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+).*'
    r'Failed password for (?:invalid user\s+)?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)'
)
SUCCESS_LOG_PATTERN = re.compile(
    r'(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+).*'
    r'Accepted password for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)'
)

def get_severity(count):
    """Determine severity based on failed attempt count"""
    if count >= 8:
        return "CRITICAL"
    elif count >= 5:
        return "HIGH"
    else:
        return "MEDIUM"

def emit_updates(app, socketio):
    """Emit current metrics via SocketIO and update database metrics"""
    global total_failed_attempts, ml_anomalies, blocked_ips
    
    data = {
        "total_failed": total_failed_attempts,
        "unique_ips": len(ip_activity),
        "blocked_ips": len(blocked_ips),
        "ml_alerts": len(ml_anomaly_list)
    }

    try:
        # Emit real-time update
        if socketio:
            socketio.emit('metrics_update', data)
            
        # Update metrics in database
        if app:
            with app.app_context():
                for key, val in data.items():
                    metric = SecurityMetric.query.filter_by(metric_name=key).order_by(SecurityMetric.timestamp.desc()).first()
                    if not metric or metric.metric_value != val:
                        new_metric = SecurityMetric(metric_name=key, metric_value=val)
                        db.session.add(new_metric)
                db.session.commit()
    except Exception as e:
        print(Fore.RED + f"[ERROR] Could not emit updates: {e}")

def monitor(app=None, socketio=None):
    """Main monitoring loop - watches log file for failed login attempts"""
    global total_failed_attempts, ml_anomalies, ml_anomaly_list
    global total_failed_attempts, ml_anomalies, ml_anomaly_list
    
    print(Fore.CYAN + "\n" + "="*70)
    print("SMART AUTHENTICATION SOC PLATFORM - MONITORING MODE".center(70))
    print("="*70)
    print(Fore.CYAN + f"Watching: {LOG_FILE_PATH}")
    print(f"Time Window: {TIME_WINDOW}s | Threshold: {ATTEMPT_THRESHOLD} attempts\n")

    try:
        ml_detector = AnomalyDetector()
        threat_api = ThreatIntelAPI()
        soar_system = AutomatedResponse(app)
        
        with open(LOG_FILE_PATH, "r", encoding="utf-8", errors="ignore") as file:
            # Start at end of file
            file.seek(0, 2)
            last_update = time.time()

            while True:
                line = file.readline()
                
                if not line:
                    # Update data every 2 seconds even if no new logs
                    if time.time() - last_update > 2:
                        emit_updates(app, socketio)
                        last_update = time.time()
                    if socketio:
                        socketio.sleep(0.5)
                    else:
                        time.sleep(0.5)
                    continue

                # Check for Successful Logins
                success_match = SUCCESS_LOG_PATTERN.search(line)
                if success_match:
                    timestamp_str = f"{success_match.group('month')} {success_match.group('day')} {success_match.group('time')}"
                    ip = success_match.group("ip")
                    user = success_match.group("user")
                    
                    geo = lookup(ip)
                    risk_score = 0
                    if geo and geo.get('country') not in ['US', 'CA', 'GB', 'IN']:
                        risk_score = 50
                        
                    is_anomalous, anomaly_score = ml_detector.record_and_check_anomaly(user, timestamp_str, location_score=risk_score)
                    
                    if is_anomalous:
                        print(Fore.MAGENTA + f"[UEBA ALERT] Anomalous successful login detected for user '{user}' from {ip} (Score: {anomaly_score:.2f})")
                        if app:
                            with app.app_context():
                                incident = Incident(
                                    incident_id=f"UEBA-{int(time.time())}",
                                    title=f"UEBA Anomaly: Unusual Login for {user}",
                                    severity="MEDIUM",
                                    source_ip=ip,
                                    location=geo.get('city', 'Unknown') if geo else 'Unknown',
                                    description=f"Unusual login pattern detected. Anomaly score: {anomaly_score:.2f}"
                                )
                                db.session.add(incident)
                                db.session.commit()
                                
                                if socketio:
                                    socketio.emit('new_threat', {
                                        'ip': ip,
                                        'severity': 'MEDIUM',
                                        'location': geo.get('city', 'Unknown') if geo else 'Unknown',
                                        'reason': f"UEBA Anomaly: {user}"
                                    })
                                
                                # Trigger playbook for anomalies
                                soar_actions = soar_system.execute_playbook("MEDIUM", ip, f"UEBA Anomaly for {user}", user)
                                for action in soar_actions:
                                    print(Fore.YELLOW + f"[SOAR ACTION taken] {action}")
                                
                                
                match = FAILED_LOG_PATTERN.search(line)
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

                        # Save block to database
                        if app:
                            with app.app_context():
                                existing_block = BlockedIP.query.filter_by(ip_address=ip).first()
                                if not existing_block:
                                    new_block = BlockedIP(
                                        ip_address=ip,
                                        severity=severity,
                                        reason=f"Brute force detection ({count} attempts)",
                                        location=location
                                    )
                                    db.session.add(new_block)
                                    db.session.commit()
                                
                                # Let's also check Threat Intel
                                reputation_score = threat_api.check_ip_reputation(ip)
                                if reputation_score > 80:
                                    print(Fore.RED + f"[THREAT INTEL] IP {ip} is KNOWN MALICIOUS globally ({reputation_score}/100)")

                                incident = Incident(
                                    incident_id=f"INC-{int(time.time())}-{count}",
                                    title=f"Brute Force Attack from {ip}",
                                    severity=severity,
                                    source_ip=ip,
                                    location=location,
                                    attack_attempts=count,
                                    description="Multiple failed login attempts detected in short time window."
                                )
                                db.session.add(incident)
                                db.session.commit()
                                
                        if socketio:
                            socketio.emit('new_threat', {
                                'ip': ip,
                                'severity': severity,
                                'location': location,
                                'reason': f"Brute force detection ({count} attempts)"
                            })
                            
                        # Trigger SOAR Playbook
                        soar_actions = soar_system.execute_playbook(severity, ip, f"Brute force detection ({count} attempts)", user)
                        for action in soar_actions:
                            print(Fore.RED + f"[SOAR ACTION taken] {action}")

                        # Check for anomalies
                        if detect_anomaly(ip, count):
                            ml_anomalies += 1
                            ml_anomaly_list.append(ip)
                            print(Fore.MAGENTA + f"[ML] 🤖 ANOMALY DETECTED from {ip}")

                    # Update data every 2 seconds
                    if time.time() - last_update > 2:
                        emit_updates(app, socketio)
                        last_update = time.time()

    except KeyboardInterrupt:
        print(Fore.CYAN + "\n\n⏹️  Monitoring stopped by user")
        emit_updates(app, socketio)
    except FileNotFoundError:
        print(Fore.RED + f"[ERROR] Log file not found: {LOG_FILE_PATH}")
        print(Fore.YELLOW + "        Create auth logs in sample_logs/web_auth.log first")
    except Exception as e:
        print(Fore.RED + f"[ERROR] {e}")
        emit_updates(app, socketio)
