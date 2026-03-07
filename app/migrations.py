"""
Database migration utilities for SMART AUTH SOC
Simple migration system without Alembic dependency
"""

import os
import json
from datetime import datetime
from app.database import db, User, BlockedIP, Incident, AuditLog

MIGRATIONS_DIR = 'app/migrations'

def ensure_migrations_dir():
    """Create migrations directory if it doesn't exist"""
    os.makedirs(MIGRATIONS_DIR, exist_ok=True)

def record_migration(name):
    """Record a migration as completed"""
    ensure_migrations_dir()
    migrations_file = os.path.join(MIGRATIONS_DIR, 'completed.json')
    
    completed = {}
    if os.path.exists(migrations_file):
        with open(migrations_file, 'r') as f:
            completed = json.load(f)
    
    completed[name] = datetime.utcnow().isoformat()
    
    with open(migrations_file, 'w') as f:
        json.dump(completed, f, indent=2)

def is_migration_completed(name):
    """Check if migration has been run"""
    migrations_file = os.path.join(MIGRATIONS_DIR, 'completed.json')
    
    if not os.path.exists(migrations_file):
        return False
    
    with open(migrations_file, 'r') as f:
        completed = json.load(f)
    
    return name in completed

def migrate_json_to_db(app):
    """
    Migrate existing JSON data to database
    Supports migration from old JSON-based system
    """
    from web.flask_app import load_users, load_soc_data
    
    with app.app_context():
        print("\n🔄 Migrating JSON data to database...\n")
        
        # Migrate users
        if not is_migration_completed('migrate_users'):
            try:
                users = {}
                try:
                    with open('web/users.json', 'r') as f:
                        users = json.load(f)
                except Exception as e:
                    print(f"Could not load users.json: {e}")
                
                migrated_count = 0
                
                for username, user_data in users.items():
                    existing = User.query.filter_by(username=username).first()
                    if not existing:
                        user = User(
                            username=username,
                            password_hash=user_data.get('password', ''),  # Already hashed in JSON
                            role=user_data.get('role', 'analyst'),
                            is_active=True,
                            created_at=datetime.fromisoformat(user_data.get('created_at', datetime.utcnow().isoformat()))
                        )
                        db.session.add(user)
                        migrated_count += 1
                
                db.session.commit()
                print(f"✓ Migrated {migrated_count} users")
                record_migration('migrate_users')
            except Exception as e:
                print(f"✗ User migration failed: {str(e)}")
                db.session.rollback()
        
        # Migrate blocked IPs
        if not is_migration_completed('migrate_blocked_ips'):
            try:
                soc_data = load_soc_data()
                blocked_ips = soc_data.get('blocked_ips', {})
                migrated_count = 0
                
                for ip, ip_data in blocked_ips.items():
                    existing = BlockedIP.query.filter_by(ip_address=ip).first()
                    if not existing:
                        blocked_ip = BlockedIP(
                            ip_address=ip,
                            severity=ip_data.get('severity', 'MEDIUM'),
                            reason=ip_data.get('reason', 'Multiple failed login attempts'),
                            location=ip_data.get('location', 'Unknown'),
                            is_permanent=ip_data.get('is_permanent', False)
                        )
                        db.session.add(blocked_ip)
                        migrated_count += 1
                
                db.session.commit()
                print(f"✓ Migrated {migrated_count} blocked IPs")
                record_migration('migrate_blocked_ips')
            except Exception as e:
                print(f"✗ Blocked IP migration failed: {str(e)}")
                db.session.rollback()
        
        print("\n✓ Database migration complete\n")

def init_sample_data(app):
    """Initialize sample data for development"""
    with app.app_context():
        # Sample incidents
        sample_incidents = [
            {
                'incident_id': 'INC-2024-001',
                'title': 'Brute Force Attack Detected',
                'severity': 'CRITICAL',
                'source_ip': '192.168.1.100',
                'attack_attempts': 45
            },
            {
                'incident_id': 'INC-2024-002',
                'title': 'Suspicious Login from New Location',
                'severity': 'HIGH',
                'source_ip': '10.0.0.50',
                'attack_attempts': 3
            }
        ]
        
        for incident_data in sample_incidents:
            if not Incident.query.filter_by(incident_id=incident_data['incident_id']).first():
                incident = Incident(**incident_data)
                db.session.add(incident)
        
        db.session.commit()
        print("✓ Sample data initialized")
