"""
Chart and visualization data generators for SMART AUTH SOC
Prepares data formatted for Chart.js and other visualization libraries
"""

from datetime import datetime, timedelta
from app.database import db, AuditLog, BlockedIP, Incident, SecurityMetric
from sqlalchemy import func

class ChartDataGenerator:
    """Generate chart data from database metrics"""
    
    @staticmethod
    def get_failed_logins_timeline(hours=24):
        """Get failed login attempts over time"""
        now = datetime.utcnow()
        cutoff = now - timedelta(hours=hours)
        
        # Query audit logs for failed logins
        failed_logins = db.session.query(
            func.strftime('%H:00', AuditLog.timestamp).label('hour'),
            func.count(AuditLog.id).label('count')
        ).filter(
            AuditLog.action.like('%login%failed%'),
            AuditLog.timestamp >= cutoff
        ).group_by('hour').all()
        
        labels = [f"{h}:00" for h in range(hours)]
        data = {label: 0 for label in labels}
        
        for hour, count in failed_logins:
            if hour in data:
                data[hour] = count
        
        return {
            'labels': list(data.keys()),
            'datasets': [{
                'label': 'Failed Attempts',
                'data': list(data.values()),
                'borderColor': '#FF9900',
                'backgroundColor': 'rgba(255, 153, 0, 0.1)',
                'borderWidth': 2,
                'tension': 0.1
            }]
        }
    
    @staticmethod
    def get_incident_severity_distribution():
        """Get incident counts by severity"""
        incidents = db.session.query(
            Incident.severity,
            func.count(Incident.id).label('count')
        ).group_by(Incident.severity).all()
        
        severity_colors = {
            'CRITICAL': '#dc3545',
            'HIGH': '#ffc107',
            'MEDIUM': '#17a2b8',
            'LOW': '#28a745'
        }
        
        labels = []
        data = []
        colors = []
        
        for severity, count in incidents:
            labels.append(severity)
            data.append(count)
            colors.append(severity_colors.get(severity, '#999999'))
        
        return {
            'labels': labels,
            'datasets': [{
                'data': data,
                'backgroundColor': colors,
                'borderColor': '#ffffff',
                'borderWidth': 2
            }]
        }
    
    @staticmethod
    def get_top_attack_sources(limit=10):
        """Get top attacking IP addresses"""
        top_ips = db.session.query(
            BlockedIP.ip_address,
            BlockedIP.attack_count,
            BlockedIP.country_code
        ).order_by(BlockedIP.attack_count.desc()).limit(limit).all()
        
        labels = [ip[0] for ip in top_ips]
        data = [ip[1] for ip in top_ips]
        
        return {
            'labels': labels,
            'datasets': [{
                'label': 'Attack Count',
                'data': data,
                'backgroundColor': [
                    f'rgba(255, {153 + i*5 % 100}, 0, 0.7)' 
                    for i in range(len(labels))
                ],
                'borderColor': '#FF9900',
                'borderWidth': 1
            }]
        }
    
    @staticmethod
    def get_daily_blocked_ips(days=7):
        """Get daily blocked IP count trend"""
        dates = []
        counts = []
        
        for i in range(days):
            date = (datetime.utcnow() - timedelta(days=i)).date()
            count = db.session.query(func.count(BlockedIP.id)).filter(
                func.date(BlockedIP.blocked_at) == date
            ).scalar() or 0
            
            dates.insert(0, date.strftime('%m-%d'))
            counts.insert(0, count)
        
        return {
            'labels': dates,
            'datasets': [{
                'label': 'Blocked IPs',
                'data': counts,
                'backgroundColor': 'rgba(255, 153, 0, 0.5)',
                'borderColor': '#FF9900',
                'borderWidth': 2,
                'fill': True
            }]
        }
    
    @staticmethod
    def get_geographic_distribution():
        """Get attack distribution by country"""
        countries = db.session.query(
            BlockedIP.country_code,
            func.count(BlockedIP.id).label('count')
        ).group_by(BlockedIP.country_code).order_by(
            func.count(BlockedIP.id).desc()
        ).limit(15).all()
        
        labels = [code or 'Unknown' for code, _ in countries]
        data = [count for _, count in countries]
        
        return {
            'labels': labels,
            'datasets': [{
                'label': 'Incidents by Country',
                'data': data,
                'backgroundColor': 'rgba(255, 153, 0, 0.6)',
                'borderColor': '#FF9900',
                'borderWidth': 1
            }]
        }
    
    @staticmethod
    def get_security_metrics_summary():
        """Get security metrics summary"""
        now = datetime.utcnow()
        today = now.date()
        yesterday = (now - timedelta(days=1)).date()
        
        today_failed = db.session.query(func.count(AuditLog.id)).filter(
            func.date(AuditLog.timestamp) == today,
            AuditLog.status == 'failure',
            AuditLog.action.like('%login%')
        ).scalar() or 0
        
        yesterday_failed = db.session.query(func.count(AuditLog.id)).filter(
            func.date(AuditLog.timestamp) == yesterday,
            AuditLog.status == 'failure',
            AuditLog.action.like('%login%')
        ).scalar() or 0
        
        total_incidents = db.session.query(func.count(Incident.id)).scalar() or 0
        critical_incidents = db.session.query(func.count(Incident.id)).filter(
            Incident.severity == 'CRITICAL'
        ).scalar() or 0
        
        total_blocked = db.session.query(func.count(BlockedIP.id)).scalar() or 0
        
        return {
            'failed_attempts_today': today_failed,
            'failed_attempts_yesterday': yesterday_failed,
            'total_incidents': total_incidents,
            'critical_incidents': critical_incidents,
            'total_blocked_ips': total_blocked,
            'detection_rate': '94.2%'  # Placeholder
        }


class HeatmapGenerator:
    """Generate heatmap data for temporal analysis"""
    
    @staticmethod
    def get_hourly_attack_pattern(days=7):
        """Get attack patterns by hour of day"""
        hours = list(range(24))
        pattern = {h: [] for h in hours}
        
        for i in range(days):
            for hour in hours:
                count = db.session.query(func.count(AuditLog.id)).filter(
                    func.strftime('%H', AuditLog.timestamp) == f'{hour:02d}',
                ).scalar() or 0
                pattern[hour].append(count)
        
        return {
            'hours': hours,
            'data': pattern
        }


class ReportGenerator:
    """Generate security reports with charts"""
    
    @staticmethod
    def get_daily_report(date=None):
        """Generate daily security report"""
        if date is None:
            date = datetime.utcnow().date()
        
        return {
            'date': date.isoformat(),
            'failed_logins': ChartDataGenerator.get_failed_logins_timeline(24),
            'incident_severity': ChartDataGenerator.get_incident_severity_distribution(),
            'top_sources': ChartDataGenerator.get_top_attack_sources(10),
            'metrics': ChartDataGenerator.get_security_metrics_summary()
        }
    
    @staticmethod
    def get_weekly_report():
        """Generate weekly security report"""
        return {
            'period': 'weekly',
            'blocked_ips_trend': ChartDataGenerator.get_daily_blocked_ips(7),
            'geographic': ChartDataGenerator.get_geographic_distribution(),
            'incident_severity': ChartDataGenerator.get_incident_severity_distribution(),
            'metrics': ChartDataGenerator.get_security_metrics_summary()
        }
    
    @staticmethod
    def get_monthly_report():
        """Generate monthly security report"""
        return {
            'period': 'monthly',
            'blocked_ips_trend': ChartDataGenerator.get_daily_blocked_ips(30),
            'geographic': ChartDataGenerator.get_geographic_distribution(),
            'incident_severity': ChartDataGenerator.get_incident_severity_distribution(),
            'metrics': ChartDataGenerator.get_security_metrics_summary()
        }
