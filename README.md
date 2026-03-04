# 🔐 SMART AUTHENTICATION SOC - Complete Web Application

A professional Security Operations Center (SOC) dashboard for monitoring authentication attacks, blocking malicious IPs, and detecting anomalies using machine learning.

## ✨ Features

### Authentication & Authorization
- ✅ Secure login system with session management
- ✅ Role-based access control (Admin, Analyst)
- ✅ Session tracking and user management
- ✅ Password hashing with werkzeug security

### Real-Time Dashboard
- ✅ Live security metrics and KPIs
- ✅ Failed login attempt tracking
- ✅ Unique attacker IP detection
- ✅ ML anomaly detection
- ✅ Auto-refreshing data (5-second intervals)

### Security Features
- ✅ Brute force attack detection
- ✅ Automatic IP blocking & firewall integration
- ✅ GeoIP location tracking
- ✅ ML-based anomaly detection
- ✅ Real-time log monitoring

### User Interface
- ✅ Modern dark-themed dashboard design
- ✅ Responsive design (mobile, tablet, desktop)
- ✅ Professional styling with gradient accents
- ✅ Multiple pages: Dashboard, Incidents, Analytics, Admin Panel
- ✅ User profile management

## 🚀 Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Run the Web Application

```bash
python run_app.py
```

The application will start on: `http://localhost:5000`

### 3. Default Login Credentials

```
Admin Account:
  Username: admin
  Password: admin123

Analyst Account:
  Username: analyst
  Password: analyst123
```

## 📁 Project Structure

```
smart-auth-soc/
├── web/
│   ├── app.py                 # Main Flask application
│   ├── users.json             # User database
│   └── templates/             # HTML templates
│       ├── login.html         # Login page
│       ├── dashboard.html     # Main dashboard
│       ├── incidents.html     # Security incidents
│       ├── analytics.html     # Analytics & metrics
│       ├── profile.html       # User profile
│       ├── admin.html         # Admin panel
│       ├── 404.html           # 404 error page
│       └── 500.html           # 500 error page
│
├── app/
│   ├── monitor.py             # Real-time log monitoring
│   ├── config.py              # Configuration
│   ├── analytics.py           # Data analytics
│   ├── firewall.py            # IP blocking
│   ├── ml_engine.py           # ML anomaly detection
│   └── geoip.py               # GeoIP lookups
│
├── sample_logs/               # Authentication logs
├── soc_data.json              # Real-time metrics
├── requirements.txt           # Python dependencies
├── run_app.py                 # Application entry point
└── README.md                  # This file
```

## 🗂️ Pages & Features

### 1. **Dashboard** (`/dashboard`)
- 4 key metrics: Failed Attempts, Unique IPs, Blocked IPs, ML Alerts
- Real-time blocked IP table
- Auto-refresh every 5 seconds
- Responsive grid layout

### 2. **Incidents** (`/incidents`)
- Severity-based filtering (Critical, High, Medium)
- Card-based incident display
- Location information for each threat
- Reason for blocking

### 3. **Analytics** (`/analytics`)
- Historical metrics
- Key performance indicators (KPIs)
- Block rate and detection rate calculations
- System status overview

### 4. **Admin Panel** (`/admin`)
- User management
- System configuration overview
- Security settings
- User roles and permissions
- Real-time user count

### 5. **User Profile** (`/profile`)
- Account information
- User permissions
- Account status
- Role information

## 🔐 Security Features

### Authentication
- Secure session management with random session IDs
- Password hashing using werkzeug.security
- Login attempt logging
- Session timeout support

### Authorization
- Role-based access control
- Admin-only endpoints
- Login requirement decorators

### Data Protection
- User data stored securely
- JSON-based local storage (can be upgraded to database)
- Audit logging for all login attempts

## 📊 Real-Time Monitoring

The system can be integrated with `monitor.py` for real-time log monitoring:

```bash
# In a separate terminal
python -m app.monitor
```

This will:
1. Watch `/sample_logs/web_auth.log` for failed login attempts
2. Detect brute force patterns
3. Block IPs at the firewall level
4. Execute ML anomaly detection
5. Update `soc_data.json` with metrics

## 🔧 Configuration

Edit `app/config.py` to customize:

```python
TIME_WINDOW = 60          # Seconds to track login attempts
ATTEMPT_THRESHOLD = 5     # Attempts before blocking
LOG_FILE_PATH = "..."     # Path to auth logs
GEOIP_API = "..."         # GeoIP service endpoint
```

## 📈 Data Flow

```
Auth Logs → Monitor → Analytics → Firewall Block
  ↓           ↓          ↓            ↓
Parsing    Detection   Metrics    Database
  ↓           ↓          ↓            ↓
Pattern    ML Check    soc_data.json Updates
  ↓           ↓          ↓            ↓
Blocking   Anomaly     Dashboard   Reports
```

## 🎨 UI/UX Highlights

- **Gradient Backgrounds**: Modern cyan-blue color scheme
- **Dark Theme**: Professional SOC aesthetic
- **Responsive Design**: Works on all screen sizes
- **Interactive Elements**: Hover effects, animations
- **Real-time Updates**: Auto-refresh without page reload
- **Severity Colors**: Visual indicators for threat levels
  - 🔴 CRITICAL (Red)
  - 🟠 HIGH (Orange)
  - 🟡 MEDIUM (Yellow)

## 🔌 API Endpoints

### Public
- `POST /login` - User login
- `GET /` - Redirect to dashboard or login

### Authenticated
- `GET /dashboard` - Main dashboard
- `GET /incidents` - Security incidents page
- `GET /analytics` - Analytics page
- `GET /profile` - User profile
- `GET /logout` - Logout user

### Admin Only
- `GET /admin` - Admin panel
- `GET /api/users` - List all users

### API Endpoints
- `GET /api/dashboard-data` - Current metrics (JSON)
- `GET /api/blocked-ips` - Blocked IP list (JSON)

## 🚦 Running the Complete System

### Terminal 1: Web Application
```bash
python run_app.py
# Server running on http://localhost:5000
```

### Terminal 2: Real-Time Monitoring (Optional)
```bash
python -m app.monitor
# Watching for authentication log events
```

Then open your browser to: `http://localhost:5000`

## 📋 Sample Log Format

The monitoring system expects logs in this format:

```
Mar 04 14:23:45 server sshd: Failed password for admin from 192.168.1.100
Mar 04 14:23:50 server sshd: Failed password for admin from 192.168.1.100
```

## 🛠️ Environment Setup

### Windows
```bash
# Create virtual environment
python -m venv .venv

# Activate virtual environment
.venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run application
python run_app.py
```

### macOS/Linux
```bash
# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run application
python run_app.py
```

## 📦 Dependencies

- **flask** (2.3.3) - Web framework
- **werkzeug** (2.3.7) - Security utilities
- **scikit-learn** (1.3.1) - Machine learning
- **numpy** (1.24.3) - Numerical computing
- **requests** (2.31.0) - HTTP client
- **colorama** (0.4.6) - Colored terminal output

## 🔮 Future Enhancements

- [ ] Database integration (PostgreSQL/MySQL)
- [ ] Advanced charting with Chart.js
- [ ] Email/Slack notifications
- [ ] LDAP/Active Directory integration
- [ ] Custom report generation
- [ ] Machine learning model improvements
- [ ] Multi-factor authentication (MFA)
- [ ] API key authentication
- [ ] Webhook integrations
- [ ] Docker containerization

## ⚖️ License

This project is for educational and demonstration purposes.

## 📞 Support

For issues or questions, please check the documentation or create an issue in the repository.

---

**Status**: ✅ Complete & Production-Ready for Demo  
**Last Updated**: March 4, 2026  
**Version**: 1.0.0
