import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from web.flask_app import app

with app.test_client() as c:
    import re
    
    # Login first
    res = c.get('/login')
    html = res.get_data(as_text=True)
    token = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
    csrf = token.group(1) if token else ""
    
    c.post('/login', data={'username': 'admin', 'password': 'admin123', 'csrf_token': csrf})
    
    # Test detection endpoints
    print("🔍 Testing Log Detection Endpoints\n" + "="*50)
    
    endpoints = [
        '/api/detection/summary',
        '/api/detection/threats',
        '/api/detection/alerts'
    ]
    
    for ep in endpoints:
        r = c.get(ep)
        print(f"\n{ep}: {r.status_code}")
        if r.status_code == 200:
            data = r.get_json()
            if isinstance(data, dict):
                for k, v in data.items():
                    if k not in ['alerts', 'threats']:
                        print(f"  {k}: {v}")
                    else:
                        count = len(v) if isinstance(v, list) else v
                        print(f"  {k}: {count} items")
    
    # Test log analysis endpoint with malicious entries to trigger detections
    print(f"\n/api/detection/analyze (POST): Testing log analysis with exploit patterns...")
    malicious_logs = [
        '192.168.1.10 - - [04/Mar/2026:12:00:00 +0000] "GET /index.php?id=1 UNION SELECT * FROM users HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
        '10.0.0.5 - - [04/Mar/2026:12:01:00 +0000] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 4321 "-" "Mozilla/5.0"',
        '172.16.0.2 - - [04/Mar/2026:12:02:00 +0000] "GET /../../etc/passwd HTTP/1.1" 403 987 "-" "curl/7.68.0"',
        'Failed password for invalid user test from 203.0.113.99 port 22 ssh2',
        'User root authentication failure for 198.51.100.23 via ssh on 04 Mar 12:03:00'
    ]
    analyze_res = c.post('/api/detection/analyze', json={'logs': malicious_logs})
    print(f"  Status: {analyze_res.status_code}")
    if analyze_res.status_code == 200:
        result = analyze_res.get_json()
        print(f"  Processed: {result.get('total_processed')} logs")
        print(f"  Detections: {len(result.get('detections', []))} found")
        print(f"  Alerts: {len(result.get('alerts', []))} triggered")
