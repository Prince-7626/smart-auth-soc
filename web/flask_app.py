import os
import json
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import secrets

# Initialize Flask app
app = Flask(__name__, template_folder='templates')
app.secret_key = secrets.token_hex(32)

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

# Initialize users file if it doesn't exist
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

# Load users
def load_users():
    with open(USERS_FILE, "r") as f:
        return json.load(f)

# Load SOC data
def load_soc_data():
    if os.path.exists(SOC_DATA_FILE):
        try:
            with open(SOC_DATA_FILE, "r") as f:
                return json.load(f)
        except:
            pass
    return {
        "total_failed": 0,
        "unique_ips": 0,
        "blocked_ips": {},
        "ml_alerts": 0
    }

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
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
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
            return render_template('login.html', error=f'Too many attempts. Try again in {retry_after} seconds.')

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
                return render_template('login.html', error=f'Too many failed attempts. Temporarily blocked for {int(BLOCK_DURATION.total_seconds()/60)} minutes.')

            return render_template('login.html', error='Invalid username or password')

    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    data = load_soc_data()
    return render_template(
        'dashboard.html',
        username=session.get('username'),
        role=session.get('role'),
        total_failed=data.get('total_failed', 0),
        unique_ips=data.get('unique_ips', 0),
        blocked_count=len(data.get('blocked_ips', {})),
        ml_alerts=data.get('ml_alerts', 0),
        blocked_ips=data.get('blocked_ips', {})
    )

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
    # Basic security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Referrer-Policy'] = 'no-referrer-when-downgrade'
    response.headers['Permissions-Policy'] = 'geolocation=()'
    # Content-Security-Policy (relaxed for templates/scripts used)
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;"
    return response


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

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)
