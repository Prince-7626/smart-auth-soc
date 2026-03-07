"""
Test log detection against real-world generated logs
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from web.flask_app import app

# Generate logs first
from tests.generate_logs import generate_auth_logs, generate_http_logs, generate_firewall_logs

with app.test_client() as c:
    import re
    
    # Login
    res = c.get('/login')
    html = res.get_data(as_text=True)
    token = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
    csrf = token.group(1) if token else ""
    c.post('/login', data={'username': 'admin', 'password': 'admin123', 'csrf_token': csrf})
    
    # Generate realistic logs
    print("🔍 Testing Log Detection Against Real-World Logs\n" + "="*60)
    
    auth_logs = generate_auth_logs(15)
    http_logs = generate_http_logs(25)
    firewall_logs = generate_firewall_logs(10)
    
    all_logs = auth_logs + http_logs + firewall_logs
    
    print(f"\n📝 Generated {len(all_logs)} logs:")
    print(f"   - Auth logs: {len(auth_logs)}")
    print(f"   - HTTP logs: {len(http_logs)}")
    print(f"   - Firewall logs: {len(firewall_logs)}")
    
    # Analyze logs
    print(f"\n🔎 Analyzing logs for threats...")
    analyze_res = c.post('/api/detection/analyze', json={'logs': all_logs})
    
    if analyze_res.status_code == 200:
        result = analyze_res.get_json()
        detections = result.get('detections', [])
        alerts = result.get('alerts', [])
        
        print(f"✓ Analysis complete:")
        print(f"   - Detections: {len(detections)}")
        print(f"   - Alerts triggered: {len(alerts)}")
        
        # Count by type
        detection_types = {}
        for detection in detections:
            if isinstance(detection, (list, tuple)) and len(detection) > 0:
                dtype = detection[0]
            elif isinstance(detection, dict):
                dtype = detection.get('type', 'unknown')
            else:
                dtype = str(detection)
            detection_types[dtype] = detection_types.get(dtype, 0) + 1
        
        if detection_types:
            print(f"\n📊 Detection breakdown:")
            for threat_type, count in sorted(detection_types.items(), key=lambda x: x[1], reverse=True):
                print(f"   - {threat_type}: {count}")
        
        # Get updated threat summary
        print(f"\n📈 Updated threat summary:")
        summary_res = c.get('/api/detection/summary')
        if summary_res.status_code == 200:
            summary = summary_res.get_json()
            print(f"   - Critical: {summary.get('critical_incidents', 0)}")
            print(f"   - High: {summary.get('high_incidents', 0)}")
            print(f"   - Medium: {summary.get('medium_incidents', 0)}")
            print(f"   - Failed logins (24h): {summary.get('failed_logins_24h', 0)}")
            print(f"   - Status: {summary.get('detection_status', '?')}")
        
        # Show threatdetected
        threats_res = c.get('/api/detection/threats')
        if threats_res.status_code == 200:
            threats_data = threats_res.get_json()
            threats = threats_data.get('threats', [])
            print(f"\n🚨 Stored threats in DB: {len(threats)}")
            for threat in threats[:5]:
                print(f"   - {threat['title'][:50]} [{threat['severity']}]")
            if len(threats) > 5:
                print(f"   ... and {len(threats) - 5} more")
