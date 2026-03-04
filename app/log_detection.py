"""
Advanced Log Detection System for SMART AUTH SOC
Detects threats, anomalies, and suspicious patterns in logs
"""

import re
import json
from datetime import datetime, timedelta
from collections import defaultdict
from app.database import db, AuditLog, Incident, BlockedIP
from sqlalchemy import func
import hashlib


class LogPattern:
    """Known attack signatures and patterns"""
    
    # Authentication patterns
    FAILED_LOGIN = re.compile(r'(Failed password|Invalid user|authentication failure|login failure)', re.IGNORECASE)
    BRUTE_FORCE = re.compile(r'(repeated failed password|multiple failed attempts|brute force)', re.IGNORECASE)
    UNAUTHORIZED_ACCESS = re.compile(r'(unauthorized|forbidden|access denied|permission denied)', re.IGNORECASE)
    
    # Web patterns
    SQL_INJECTION = re.compile(r"(union|select|insert|delete|drop|exec|script|--|;|\*)", re.IGNORECASE)
    XSS_ATTACK = re.compile(r"(<script|javascript:|on\w+\s*=|alert\(|eval\(|onerror)", re.IGNORECASE)
    PATH_TRAVERSAL = re.compile(r"(\.\.\/|\.\.\\|%2e%2e|\.\.%2f|\.\.%5c)", re.IGNORECASE)
    
    # Suspicious patterns
    SUSPICIOUS_PORT = re.compile(r":(22|23|3306|5432|27017|6379|9200|50070)")
    SUSPICIOUS_PROTOCOL = re.compile(r"(telnet|ftp|raw|cmd)", re.IGNORECASE)
    SCANNING = re.compile(r"(port scan|vulnerability scan|nmap|masscan|shodan|nessus)", re.IGNORECASE)
    BOT_ACTIVITY = re.compile(r"(bot|crawler|scanner|spider|probe)", re.IGNORECASE)
    
    # Data exfiltration patterns
    LARGE_TRANSFER = re.compile(r"(\d+\s*(GB|MB|TB)|transferred|uploaded|downloaded)")
    SUSPICIOUS_DOMAIN = re.compile(r"(pastebin|cron|bit\.ly|tinyurl|bit\.do|goo\.gl)")
    

class LogDetectionEngine:
    """Main log detection and analysis engine"""
    
    def __init__(self):
        self.alerts = []
        self.detections = defaultdict(list)
        self.ip_reputation = {}
        self.user_baseline = defaultdict(dict)
        
    def parse_syslog(self, log_line):
        """Parse standard syslog format"""
        pattern = re.compile(
            r'(?P<timestamp>\w+ +\d+ \d+:\d+:\d+) '
            r'(?P<hostname>\S+) '
            r'(?P<process>\w+)(?:\[(?P<pid>\d+)\])?: '
            r'(?P<message>.*)'
        )
        match = pattern.search(log_line)
        if match:
            return {
                'timestamp': match.group('timestamp'),
                'hostname': match.group('hostname'),
                'process': match.group('process'),
                'pid': match.group('pid'),
                'message': match.group('message'),
                'raw': log_line
            }
        return None
    
    def parse_http_log(self, log_line):
        """Parse Apache/Nginx HTTP log format"""
        pattern = re.compile(
            r'(?P<ip>\d+\.\d+\.\d+\.\d+) - (?P<user>\S+) '
            r'\[(?P<timestamp>[^\]]+)\] '
            r'"(?P<method>\w+) (?P<path>\S+) (?P<protocol>\S+)" '
            r'(?P<status>\d+) (?P<bytes>\d+|-) '
            r'"(?P<referrer>[^"]*)" "(?P<useragent>[^"]*)"'
        )
        match = pattern.search(log_line)
        if match:
            return {
                'ip': match.group('ip'),
                'user': match.group('user'),
                'timestamp': match.group('timestamp'),
                'method': match.group('method'),
                'path': match.group('path'),
                'status': int(match.group('status')),
                'bytes': int(match.group('bytes')) if match.group('bytes') != '-' else 0,
                'referrer': match.group('referrer'),
                'useragent': match.group('useragent'),
                'raw': log_line
            }
        return None
    
    def parse_ssh_log(self, log_line):
        """Parse SSH/auth log format"""
        pattern = re.compile(
            r'(Failed password|Invalid user|authentication failure|Accepted) '
            r'(?:for |user |)(?P<user>\S+)? '
            r'from (?P<ip>\d+\.\d+\.\d+\.\d+)|'
            r'(keyboard-interactive|publickey|password) '
            r'for (?P<user2>\S+) from (?P<ip2>\d+\.\d+\.\d+\.\d+)'
        )
        match = pattern.search(log_line)
        if match:
            user = match.group('user') or match.group('user2')
            ip = match.group('ip') or match.group('ip2')
            return {
                'user': user,
                'ip': ip,
                'success': 'Accepted' in log_line,
                'raw': log_line
            }
        return None
    
    def detect_pattern(self, log_data):
        """Detect known attack patterns in log"""
        detections = []
        
        # Combine all text fields for pattern matching
        text = ' '.join(str(v) for v in log_data.values() if isinstance(v, str))
        
        # Check attack patterns
        if LogPattern.SQL_INJECTION.search(text):
            detections.append(('SQL_INJECTION', 'HIGH', 'Possible SQL injection attempt'))
        
        if LogPattern.XSS_ATTACK.search(text):
            detections.append(('XSS_ATTACK', 'HIGH', 'Possible XSS attack attempt'))
        
        if LogPattern.PATH_TRAVERSAL.search(text):
            detections.append(('PATH_TRAVERSAL', 'HIGH', 'Possible path traversal attempt'))
        
        if LogPattern.BRUTE_FORCE.search(text):
            detections.append(('BRUTE_FORCE', 'CRITICAL', 'Brute force attack detected'))
        
        if LogPattern.UNAUTHORIZED_ACCESS.search(text):
            detections.append(('UNAUTHORIZED_ACCESS', 'MEDIUM', 'Unauthorized access attempt'))
        
        if LogPattern.SCANNING.search(text):
            detections.append(('NETWORK_SCAN', 'MEDIUM', 'Network scanning activity detected'))
        
        if LogPattern.BOT_ACTIVITY.search(text):
            detections.append(('BOT_ACTIVITY', 'LOW', 'Automated bot/crawler activity'))
        
        if LogPattern.SUSPICIOUS_DOMAIN.search(text):
            detections.append(('SUSPICIOUS_DOMAIN', 'MEDIUM', 'Communication with suspicious domain'))
        
        if LogPattern.SUSPICIOUS_PORT.search(text):
            detections.append(('SUSPICIOUS_PORT', 'MEDIUM', 'Connection to suspicious port'))
        
        return detections
    
    def detect_brute_force(self, logs, ip_address, threshold=5, time_window=300):
        """Detect brute force attacks on IP"""
        failed_attempts = 0
        
        # Query recent failed logins from this IP
        cutoff_time = datetime.utcnow() - timedelta(seconds=time_window)
        attempts = db.session.query(AuditLog).filter(
            AuditLog.source_ip == ip_address,
            AuditLog.action.like('%login%failed%'),
            AuditLog.timestamp >= cutoff_time
        ).count()
        
        if attempts >= threshold:
            return True, {
                'type': 'BRUTE_FORCE',
                'severity': 'CRITICAL',
                'ip': ip_address,
                'attempt_count': attempts,
                'time_window': f'{time_window}s',
                'description': f'Brute force attack detected: {attempts} failed logins in {time_window}s'
            }
        
        return False, None
    
    def detect_anomalous_behavior(self, ip_address, user=None):
        """Detect anomalous user/IP behavior using ML"""
        detections = []
        
        # Check for unusual login times
        recent_logins = db.session.query(AuditLog).filter(
            AuditLog.source_ip == ip_address,
            AuditLog.action.like('%login%success%'),
            AuditLog.timestamp >= datetime.utcnow() - timedelta(days=7)
        ).all()
        
        if recent_logins:
            hours = [login.timestamp.hour for login in recent_logins]
            # Flag if logins at unusual hours (e.g., 2 AM when user typically logs in at 9 AM)
            avg_hour = sum(hours) / len(hours) if hours else 0
            for login in recent_logins[-3:]:  # Check last 3 logins
                if abs(login.timestamp.hour - avg_hour) > 4:
                    detections.append({
                        'type': 'UNUSUAL_LOGIN_TIME',
                        'severity': 'MEDIUM',
                        'description': f'Login at unusual time: {login.timestamp.hour}:00 (typical: {int(avg_hour)}:00)'
                    })
        
        # Check for geographic anomalies (impossible travel)
        if recent_logins and len(recent_logins) >= 2:
            last_two = sorted(recent_logins, key=lambda x: x.timestamp)[-2:]
            time_diff = (last_two[1].timestamp - last_two[0].timestamp).total_seconds() / 3600
            if time_diff < 1:  # Less than 1 hour between attempts
                detections.append({
                    'type': 'IMPOSSIBLE_TRAVEL',
                    'severity': 'HIGH',
                    'description': 'Multiple logins from different locations within <1 hour'
                })
        
        return detections
    
    def detect_privilege_escalation(self, user, action):
        """Detect attempts to escalate privileges"""
        escalation_keywords = ['sudo', 'su', 'admin', 'root', 'wheel', 'privilege', 'grant', 'chmod', '777']
        
        if any(keyword in action.lower() for keyword in escalation_keywords):
            recent_user_actions = db.session.query(AuditLog).filter(
                AuditLog.details.like(f'%{user}%'),
                AuditLog.timestamp >= datetime.utcnow() - timedelta(hours=1)
            ).count()
            
            if recent_user_actions >= 3:
                return {
                    'type': 'PRIVILEGE_ESCALATION',
                    'severity': 'HIGH',
                    'user': user,
                    'actions': recent_user_actions,
                    'description': f'Possible privilege escalation: {recent_user_actions} suspicious actions in 1 hour'
                }
        
        return None
    
    def detect_data_exfiltration(self, log_data):
        """Detect potential data exfiltration"""
        detections = []
        
        # Check for large file transfers
        if LogPattern.LARGE_TRANSFER.search(str(log_data)):
            detections.append({
                'type': 'LARGE_TRANSFER',
                'severity': 'HIGH',
                'description': 'Large data transfer detected - possible exfiltration'
            })
        
        # Check for suspicious external domains
        if LogPattern.SUSPICIOUS_DOMAIN.search(str(log_data)):
            detections.append({
                'type': 'SUSPICIOUS_EXTERNAL_CONTACT',
                'severity': 'MEDIUM',
                'description': 'Communication with known suspicious domain'
            })
        
        return detections
    
    def generate_alert(self, detection_type, severity, ip_address, description, log_data=None):
        """Generate security alert and store in database"""
        alert = {
            'timestamp': datetime.utcnow(),
            'type': detection_type,
            'severity': severity,
            'ip_address': ip_address,
            'description': description,
            'log_data': log_data
        }
        
        # Store as incident in database
        try:
            incident = Incident(
                incident_id=f"INC-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{hash(ip_address) % 10000}",
                title=f"{detection_type}: {description[:60]}",
                severity=severity,
                status='OPEN',
                source_ip=ip_address,
                location=getattr(log_data, 'location', 'Unknown') if log_data else 'Unknown',
                attack_attempts=1,
                created_at=datetime.utcnow()
            )
            db.session.add(incident)
            db.session.commit()
            
            # Also block the IP if CRITICAL
            if severity == 'CRITICAL':
                self._block_ip(ip_address, detection_type)
        
        except Exception as e:
            print(f"Error storing alert: {e}")
        
        self.alerts.append(alert)
        return alert
    
    def _block_ip(self, ip_address, reason):
        """Block malicious IP"""
        try:
            blocked = BlockedIP.query.filter_by(ip_address=ip_address).first()
            if not blocked:
                blocked = BlockedIP(
                    ip_address=ip_address,
                    severity='CRITICAL',
                    reason=reason,
                    location='Unknown',
                    country_code='??',
                    attack_count=1,
                    first_seen=datetime.utcnow(),
                    last_seen=datetime.utcnow(),
                    blocked_at=datetime.utcnow(),
                    is_permanent=True,
                    is_whitelisted=False
                )
                db.session.add(blocked)
            else:
                blocked.attack_count += 1
                blocked.last_seen = datetime.utcnow()
            
            db.session.commit()
        except Exception as e:
            print(f"Error blocking IP: {e}")
    
    def process_log_stream(self, log_lines):
        """Process a stream of logs and detect threats"""
        results = {
            'total_processed': 0,
            'detections': [],
            'alerts': []
        }
        
        for log_line in log_lines:
            results['total_processed'] += 1
            
            # Try different parsers
            log_data = (
                self.parse_syslog(log_line) or
                self.parse_http_log(log_line) or
                self.parse_ssh_log(log_line) or
                {'raw': log_line}
            )
            
            # Pattern matching
            patterns = self.detect_pattern(log_data)
            if patterns:
                results['detections'].extend(patterns)
                
                # Generate alerts for high severity
                for pattern_type, severity, description in patterns:
                    if severity in ['HIGH', 'CRITICAL']:
                        ip = log_data.get('ip') or log_data.get('source_ip', 'unknown')
                        alert = self.generate_alert(pattern_type, severity, ip, description, log_data)
                        results['alerts'].append(alert)
        
        return results
    
    def get_threat_summary(self):
        """Get summary of detected threats"""
        summary = {
            'total_alerts': len(self.alerts),
            'critical': sum(1 for a in self.alerts if a['severity'] == 'CRITICAL'),
            'high': sum(1 for a in self.alerts if a['severity'] == 'HIGH'),
            'medium': sum(1 for a in self.alerts if a['severity'] == 'MEDIUM'),
            'low': sum(1 for a in self.alerts if a['severity'] == 'LOW'),
            'top_threats': self._get_top_threats(5),
            'most_active_ips': self._get_most_active_ips(10)
        }
        return summary
    
    def _get_top_threats(self, limit=5):
        """Get top threat types"""
        types = defaultdict(int)
        for alert in self.alerts:
            types[alert['type']] += 1
        return sorted(types.items(), key=lambda x: x[1], reverse=True)[:limit]
    
    def _get_most_active_ips(self, limit=10):
        """Get IPs with most alerts"""
        ips = defaultdict(int)
        for alert in self.alerts:
            ips[alert['ip_address']] += 1
        return sorted(ips.items(), key=lambda x: x[1], reverse=True)[:limit]


# Initialize global detection engine
detection_engine = LogDetectionEngine()
