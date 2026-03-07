import os
import json
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_socketio import SocketIO
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize Flask app
FRONTEND_DIST = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'frontend', 'dist')
app = Flask(__name__, template_folder='templates', static_folder=os.path.join(FRONTEND_DIST, 'assets'), static_url_path='/assets')
app.secret_key = os.getenv('SECRET_KEY', 'default-static-secret-key-soc-platform-12345')

# Initialize SocketIO
socketio = SocketIO(app, cors_allowed_origins="*")

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///smartauth_soc.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Import and initialize database
from app.database import db, init_db, User, BlockedIP, Incident, AuditLog
from app.migrations import migrate_json_to_db
from app.security import (
    InputValidator, CSRFProtection, RateLimiter, 
    SecurityHeaders, APIAuth, require_api_key, rate_limit
)
from app.charts import ChartDataGenerator

db.init_app(app)

# Session lifetime
app.permanent_session_lifetime = timedelta(minutes=30)

# Simple in-memory login attempt tracker to protect the login endpoint
# Structure: { ip: {"count": int, "first_seen": datetime, "blocked_until": datetime or None} }
login_attempts = {}
LOGIN_ATTEMPT_WINDOW = timedelta(minutes=15)
LOGIN_ATTEMPT_THRESHOLD = 6
BLOCK_DURATION = timedelta(minutes=10)

# Base directory configuration
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_FILE = os.path.join(BASE_DIR, "sample_logs", "web_auth.log")
SOC_DATA_FILE = os.path.join(BASE_DIR, "soc_data.json")
USERS_FILE = os.path.join(BASE_DIR, "web", "users.json")

# Ensure directories exist
os.makedirs(os.path.join(BASE_DIR, "sample_logs"), exist_ok=True)

# Initialize users file if it doesn't exist (for backwards compatibility)
def init_users():
    if not os.path.exists(USERS_FILE):
        users = {
            "admin": {
                "password": generate_password_hash("admin123"),
                "role": "admin",
                "created_at": datetime.now().isoformat()
            },
            "analyst": {
                "password": generate_password_hash("analyst123"),
                "role": "analyst",
                "created_at": datetime.now().isoformat()
            }
        }
        with open(USERS_FILE, "w") as f:
            json.dump(users, f, indent=4)

init_users()

# Initialize database with Flask context
with app.app_context():
    db.create_all()
    print("✓ Database initialized")
    # Migrate existing JSON data to database
    try:
        migrate_json_to_db(app)
    except Exception as e:
        print(f"Note: Migration not needed or already completed")


# Load users
def load_users():
    users_dict = {}
    with app.app_context():
        users_db = User.query.all()
        for u in users_db:
            users_dict[u.username] = {
                "password": u.password_hash,
                "role": u.role,
                "created_at": u.created_at.isoformat() if u.created_at else "Unknown"
            }
    return users_dict

# Load SOC data
def load_soc_data():
    with app.app_context():
        # get blocked IPs
        blocked_ips_db = BlockedIP.query.all()
        blocked_ips = {}
        for b in blocked_ips_db:
            blocked_ips[b.ip_address] = {
                "severity": b.severity,
                "reason": b.reason,
                "location": b.location,
                "blocked_at": b.blocked_at.strftime("%Y-%m-%d %H:%M:%S") if b.blocked_at else "Unknown"
            }
            
        total_failed = AuditLog.query.filter_by(status='failure').count()
        from sqlalchemy import func
        unique_ips = db.session.query(func.count(func.distinct(AuditLog.source_ip))).scalar() or 0
        ml_alerts = Incident.query.count()
        
        return {
            "total_failed": total_failed,
            "unique_ips": unique_ips,
            "blocked_ips": blocked_ips,
            "ml_alerts": ml_alerts
        }

# Audit logging helper
def log_audit_event(action, status='success', resource_type=None, resource_id=None, details=None):
    """Log security audit events to database"""
    try:
        username = session.get('username')
        user = User.query.filter_by(username=username).first() if username else None
        
        audit_log = AuditLog(
            user_id=user.id if user else None,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            status=status,
            details=details,
            source_ip=request.remote_addr,
            user_agent=request.headers.get('User-Agent', '')[:500]
        )
        db.session.add(audit_log)
        db.session.commit()
    except Exception as e:
        print(f"Audit logging error: {str(e)}")

# API enrichment helper
def enrich_ip_data(ip_address):
    """Enrich IP data with geolocation and threat information"""
    try:
        from app.api_integrations import APIAggregator
        return APIAggregator.enrich_threat_data(ip_address)
    except Exception as e:
        print(f"IP enrichment error: {str(e)}")
        return {'ip': ip_address, 'location': 'Unknown', 'threat_score': 0, 'error': str(e)}

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        users = load_users()
        if users[session['username']].get('role') != 'admin':
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Routes

@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        # Generate CSRF token for form
        csrf_token = CSRFProtection.generate_token()
        session['csrf_token'] = csrf_token
        return render_template('login.html', csrf_token=csrf_token)
    
    if request.method == 'POST':
        # Validate CSRF token
        csrf_token = request.form.get('csrf_token')
        stored_token = session.get('csrf_token')
        
        # Provide a token for re-rendering the form on errors
        display_token = stored_token if stored_token else CSRFProtection.generate_token()
        session['csrf_token'] = display_token
        
        if not csrf_token or not stored_token or not CSRFProtection.validate_token(csrf_token, stored_token):
            return render_template('login.html', error='Security validation failed. Please try again.', csrf_token=display_token), 403
        
        # Get and validate inputs
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        # Input validation
        try:
            username = InputValidator.sanitize_string(username, max_length=80)
            if not InputValidator.validate_username(username):
                raise ValueError("Invalid username format")
        except ValueError as e:
            log_audit_event('login_attempt', 'failure', resource_type='authentication', details={'reason': str(e), 'username': username})
            return render_template('login.html', error='Invalid username or password.', csrf_token=display_token)
        
        users = load_users()

        # Log login attempt
        ip = request.remote_addr
        timestamp = datetime.now().strftime("%b %d %H:%M:%S")
        log_entry = f"{timestamp} server login[attempt]: username={username} from {ip}\n"
        with open(LOG_FILE, "a") as f:
            f.write(log_entry)

        # Track attempts and enforce temporary blocks
        now = datetime.utcnow()
        state = login_attempts.get(ip)
        if state:
            if now - state['first_seen'] > LOGIN_ATTEMPT_WINDOW:
                state = {"count": 0, "first_seen": now, "blocked_until": None}
        else:
            state = {"count": 0, "first_seen": now, "blocked_until": None}

        if state.get('blocked_until') and now < state['blocked_until']:
            retry_after = int((state['blocked_until'] - now).total_seconds())
            log_audit_event('login_attempt', 'failure', resource_type='authentication', details={'reason': 'rate_limited', 'ip': ip})
            return render_template('login.html', error=f'Too many attempts. Try again in {retry_after} seconds.', csrf_token=display_token)

        # Check credentials
        if username in users and check_password_hash(users[username]['password'], password):
            session['username'] = username
            session['role'] = users[username].get('role', 'analyst')
            session_id = secrets.token_hex(16)
            session['session_id'] = session_id
            session.permanent = True

            # successful login clears attempts for this IP
            if ip in login_attempts:
                login_attempts.pop(ip, None)
            log_entry = f"{timestamp} server login[success]: username={username} from {ip} session={session_id}\n"
            with open(LOG_FILE, "a") as f:
                f.write(log_entry)
            
            log_audit_event('login_success', 'success', resource_type='authentication', details={'username': username, 'ip': ip})
            return redirect(url_for('dashboard'))
        else:
            log_entry = f"{timestamp} server login[failed]: username={username} from {ip} reason=invalid_credentials\n"
            with open(LOG_FILE, "a") as f:
                f.write(log_entry)

            # increment failed attempt
            state['count'] += 1
            login_attempts[ip] = state

            if state['count'] >= LOGIN_ATTEMPT_THRESHOLD:
                state['blocked_until'] = now + BLOCK_DURATION
                login_attempts[ip] = state
                return render_template('login.html', error=f'Too many failed attempts. Temporarily blocked for {int(BLOCK_DURATION.total_seconds()/60)} minutes.', csrf_token=display_token)

            return render_template('login.html', error='Invalid username or password', csrf_token=display_token)

    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    from flask import send_from_directory
    return send_from_directory(FRONTEND_DIST, 'index.html')
@app.route('/api/incidents')
@login_required
def api_incidents():
    try:
        incidents = Incident.query.order_by(Incident.timestamp.desc()).limit(100).all()
        return jsonify([
            {
                "id": inc.id,
                "incident_id": inc.incident_id,
                "title": inc.title,
                "severity": inc.severity,
                "ip": inc.source_ip,
                "location": inc.location,
                "reason": inc.description,
                "timestamp": inc.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            } for inc in incidents
        ])
    except Exception as e:
        return jsonify([])

@app.route('/api/dashboard-data')
@login_required
def api_dashboard_data():
    data = load_soc_data()
    
    # Calculate stats
    blocked_ips = data.get('blocked_ips', {})
    blocked_by_severity = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0}
    
    for ip, info in blocked_ips.items():
        severity = info.get('severity', 'MEDIUM')
        if severity in blocked_by_severity:
            blocked_by_severity[severity] += 1
    
    return jsonify({
        'total_failed': data.get('total_failed', 0),
        'unique_ips': data.get('unique_ips', 0),
        'blocked_ips': len(blocked_ips),
        'ml_alerts': data.get('ml_alerts', 0),
        'blocked_by_severity': blocked_by_severity,
        'last_updated': datetime.now().isoformat()
    })

@app.route('/api/blocked-ips')
@login_required
def api_blocked_ips():
    data = load_soc_data()
    blocked_ips = data.get('blocked_ips', {})
    
    # Format for table
    ips = []
    for ip, info in blocked_ips.items():
        ips.append({
            'ip': ip,
            'severity': info.get('severity', 'UNKNOWN'),
            'blocked_at': info.get('blocked_at', 'N/A'),
            'reason': info.get('reason', 'Suspicious activity')
        })
    
    return jsonify(ips)

@app.route('/incidents')
@login_required
def incidents():
    data = load_soc_data()
    blocked_ips = data.get('blocked_ips', {})
    
    incidents = []
    for ip, info in blocked_ips.items():
        incidents.append({
            'ip': ip,
            'severity': info.get('severity', 'MEDIUM'),
            'reason': info.get('reason', 'Multiple failed login attempts'),
            'blocked_at': info.get('blocked_at', 'Unknown'),
            'location': info.get('location', 'Unknown')
        })
    
    # Sort by severity
    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2}
    incidents.sort(key=lambda x: severity_order.get(x['severity'], 3))
    
    return render_template('incidents.html', incidents=incidents, username=session.get('username'))

@app.route('/analytics')
@login_required
def analytics():
    data = load_soc_data()
    
    stats = {
        'total_failed': data.get('total_failed', 0),
        'unique_ips': data.get('unique_ips', 0),
        'blocked_ips': len(data.get('blocked_ips', {})),
        'ml_alerts': data.get('ml_alerts', 0)
    }
    
    return render_template('analytics.html', stats=stats, username=session.get('username'))

@app.route('/profile')
@login_required
def profile():
    users = load_users()
    user = users.get(session['username'], {})
    return render_template(
        'profile.html',
        username=session['username'],
        role=session.get('role'),
        user_data=user
    )

@app.route('/admin')
@admin_required
def admin_panel():
    return render_template('admin.html', username=session['username'])

@app.route('/api/users')
@admin_required
def api_users():
    users = load_users()
    user_list = []
    for username, data in users.items():
        user_list.append({
            'username': username,
            'role': data.get('role', 'analyst'),
            'created_at': data.get('created_at', 'Unknown')
        })
    return jsonify(user_list)

# Chart API Endpoints
@app.route('/api/charts/failed-logins')
@login_required
def api_failed_logins():
    """Get failed login attempts timeline data for Chart.js"""
    try:
        hours = request.args.get('hours', 24, type=int)
        chart_data = ChartDataGenerator.get_failed_logins_timeline(hours)
        return jsonify(chart_data)
    except Exception as e:
        app.logger.error(f"Error generating failed logins chart: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/charts/incident-severity')
@login_required
def api_incident_severity():
    """Get incident severity distribution data for Chart.js"""
    try:
        chart_data = ChartDataGenerator.get_incident_severity_distribution()
        return jsonify(chart_data)
    except Exception as e:
        app.logger.error(f"Error generating severity chart: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/charts/blocked-ips-trend')
@login_required
def api_blocked_ips_trend():
    """Get daily blocked IPs trend data for Chart.js"""
    try:
        days = request.args.get('days', 7, type=int)
        chart_data = ChartDataGenerator.get_daily_blocked_ips(days)
        return jsonify(chart_data)
    except Exception as e:
        app.logger.error(f"Error generating blocked IPs trend chart: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/charts/geographic')
@login_required
def api_geographic_distribution():
    """Get geographic attack distribution data for Chart.js"""
    try:
        chart_data = ChartDataGenerator.get_geographic_distribution()
        return jsonify(chart_data)
    except Exception as e:
        app.logger.error(f"Error generating geographic chart: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/charts/top-sources')
@login_required
def api_top_sources():
    """Get top attack sources data for Chart.js"""
    try:
        limit = request.args.get('limit', 10, type=int)
        chart_data = ChartDataGenerator.get_top_attack_sources(limit)
        return jsonify(chart_data)
    except Exception as e:
        app.logger.error(f"Error generating top sources chart: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/metrics/summary')
@login_required
def api_metrics_summary():
    """Get security metrics summary"""
    try:
        metrics = ChartDataGenerator.get_security_metrics_summary()
        return jsonify(metrics)
    except Exception as e:
        app.logger.error(f"Error generating metrics summary: {e}")
        return jsonify({'error': str(e)}), 500

# Log Detection API Endpoints
@app.route('/api/detection/threats')
@login_required
def api_detection_threats():
    """Get detected threats from database"""
    try:
        # Query recent incidents from database
        from app.database import Incident
        recent_incidents = db.session.query(Incident).filter(
            Incident.created_at >= datetime.utcnow() - timedelta(days=7)
        ).order_by(Incident.created_at.desc()).limit(50).all()
        
        threats = []
        for inc in recent_incidents:
            threats.append({
                'id': inc.incident_id,
                'title': inc.title,
                'severity': inc.severity,
                'source_ip': inc.source_ip,
                'status': inc.status,
                'created_at': inc.created_at.isoformat(),
                'attack_attempts': inc.attack_attempts
            })
        
        return jsonify({'threats': threats, 'total': len(threats)})
    except Exception as e:
        app.logger.error(f"Error fetching threats: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/detection/alerts')
@login_required
def api_detection_alerts():
    """Get recent security alerts"""
    try:
        from app.database import AuditLog
        limit = request.args.get('limit', 20, type=int)
        
        # Get recent failed login attempts and suspicious activities
        alerts = db.session.query(AuditLog).filter(
            AuditLog.status == 'failure',
            AuditLog.timestamp >= datetime.utcnow() - timedelta(hours=24)
        ).order_by(AuditLog.timestamp.desc()).limit(limit).all()
        
        alert_list = []
        for alert in alerts:
            alert_list.append({
                'id': alert.id,
                'action': alert.action,
                'status': alert.status,
                'source_ip': alert.source_ip,
                'timestamp': alert.timestamp.isoformat(),
                'details': alert.details
            })
        
        return jsonify({'alerts': alert_list, 'total': len(alert_list)})
    except Exception as e:
        app.logger.error(f"Error fetching alerts: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/detection/summary')
@login_required
def api_detection_summary():
    """Get threat detection summary"""
    try:
        from app.database import Incident, BlockedIP, AuditLog
        from sqlalchemy import func
        
        # Count incidents by severity (last 7 days)
        cutoff = datetime.utcnow() - timedelta(days=7)
        severity_counts = db.session.query(
            Incident.severity,
            func.count(Incident.id).label('count')
        ).filter(Incident.created_at >= cutoff).group_by(Incident.severity).all()
        
        severities = {s[0]: s[1] for s in severity_counts}
        
        # Count blocked IPs
        total_blocked = BlockedIP.query.count()
        recently_blocked = BlockedIP.query.filter(
            BlockedIP.blocked_at >= cutoff
        ).count()
        
        # Count failed logins (last 24 hours)
        failed_logins = AuditLog.query.filter(
            AuditLog.status == 'failure',
            AuditLog.timestamp >= datetime.utcnow() - timedelta(hours=24)
        ).count()
        
        summary = {
            'critical_incidents': severities.get('CRITICAL', 0),
            'high_incidents': severities.get('HIGH', 0),
            'medium_incidents': severities.get('MEDIUM', 0),
            'low_incidents': severities.get('LOW', 0),
            'total_blocked_ips': total_blocked,
            'recently_blocked': recently_blocked,
            'failed_logins_24h': failed_logins,
            'detection_status': 'ACTIVE'
        }
        
        return jsonify(summary)
    except Exception as e:
        app.logger.error(f"Error generating detection summary: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/detection/analyze', methods=['POST'])
@login_required
def api_detection_analyze():
    """Analyze logs for threats"""
    try:
        from app.log_detection import detection_engine
        
        # Get log lines from request
        data = request.get_json()
        log_lines = data.get('logs', [])
        
        if not log_lines:
            return jsonify({'error': 'No logs provided'}), 400
        
        # Process logs
        results = detection_engine.process_log_stream(log_lines)
        
        return jsonify(results)
    except Exception as e:
        app.logger.error(f"Error analyzing logs: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/logs/upload', methods=['POST'])
@login_required
def api_logs_upload():
    """Upload new logs to the monitoring system"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
            
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
            
        # Append lines to web_auth.log
        contents = file.read().decode('utf-8')
        if not contents:
            return jsonify({'error': 'File is empty'}), 400

        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(contents)
            if not contents.endswith('\n'):
                f.write('\n')
                
        # Count lines for response
        lines = len(contents.splitlines())
        log_audit_event('log_upload', 'success', resource_type='system_logs', details={'filename': file.filename, 'lines': lines})
        
        return jsonify({'success': True, 'message': f'Successfully queued {lines} log entries for analysis'})
    except Exception as e:
        app.logger.error(f"Error uploading logs: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/logout')
def logout():
    username = session.get('username')
    if username:
        ip = request.remote_addr
        timestamp = datetime.now().strftime("%b %d %H:%M:%S")
        log_entry = f"{timestamp} server logout[success]: username={username} from {ip}\n"
        with open(LOG_FILE, "a") as f:
            f.write(log_entry)
    
    session.clear()
    return redirect(url_for('login'))


@app.after_request
def set_security_headers(response):
    # Apply comprehensive security headers
    return SecurityHeaders.apply_headers(response)


@app.route('/favicon.ico')
def favicon():
    # Return a tiny SVG favicon so browsers don't 404
    svg = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">'
        '<rect width="64" height="64" rx="8" ry="8" fill="#0f1724"/>'
        '<text x="50%" y="54%" font-size="36" text-anchor="middle" fill="#00d4ff" font-family="Segoe UI,Arial">🔐</text>'
        '</svg>'
    )
    from flask import Response
    return Response(svg, mimetype='image/svg+xml')

@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(error):
    return render_template('500.html'), 500

def start_monitor():
    from app.monitor import monitor
    monitor(app, socketio)

if __name__ == '__main__':
    # Start the monitor in a background thread
    socketio.start_background_task(start_monitor)
    socketio.run(app, host='127.0.0.1', port=5000, debug=True, use_reloader=False)
