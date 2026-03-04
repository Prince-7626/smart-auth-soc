import sys, os
import re
from flask import session

# ensure root directory is on path
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from web.flask_app import app

print("Testing Chart API Integration\n" + "="*50)

with app.test_client() as client:
    # Get CSRF token
    res = client.get('/login')
    html = res.get_data(as_text=True)
    csrf_match = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
    csrf_token = csrf_match.group(1) if csrf_match else ""
    
    print(f"\n✓ CSRF token extracted: {csrf_token[:15]}..." if csrf_token else "✗ No CSRF token")
    
    # Try login and capture session
    login_res = client.post('/login', data={
        'username': 'admin',
        'password': 'admin123',
        'csrf_token': csrf_token
    }, follow_redirects=True)
    
    # Check session after login
    with client.session_transaction() as sess:
        username = sess.get('username')
        role = sess.get('role')
        print(f"✓ Session data: username={username}, role={role}")
        
        if username:
            # Now test chart endpoints with session
            print("\n📊 Testing Chart Endpoints:\n")
            endpoints = [
                '/api/charts/failed-logins',
                '/api/charts/incident-severity',
                '/api/charts/geographic',
                '/api/charts/blocked-ips-trend',
                '/api/charts/top-sources',
                '/api/metrics/summary'
            ]
            
            success = 0
            for ep in endpoints:
                r = client.get(ep)
                if r.status_code == 200:
                    data = r.get_json()
                    labels_str = f"- {len(data.get('labels', []))} labels" if 'labels' in data else "- summary data"
                    print(f"✓ {ep}: 200 OK {labels_str}")
                    success += 1
                else:
                    print(f"✗ {ep}: {r.status_code}")
            
            print(f"\n✅ Summary: {success}/{len(endpoints)} endpoints working\n")




