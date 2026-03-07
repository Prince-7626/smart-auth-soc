#!/usr/bin/env python3
"""
SMART AUTH SOC - Complete Web Application
Production-ready Security Operations Center Dashboard
"""

import sys
import os
import threading
import webbrowser

# Ensure imports work correctly
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from web.flask_app import app, socketio, start_monitor

if __name__ == '__main__':
    print("\n" + "="*70)
    print("🔐 SMART AUTHENTICATION SOC PLATFORM".center(70))
    print("Security Operations Center Dashboard".center(70))
    print("="*70)
    print("\n📍 Starting Flask Application...")
    print("   URL: http://localhost:5000")
    print("   Login: admin / admin123 (or analyst / analyst123)")
    print("\n🚀 Press Ctrl+C to stop the server")
    print("="*70 + "\n")
    
    try:
        socketio.start_background_task(start_monitor)
        threading.Timer(1.5, lambda: webbrowser.open_new("http://localhost:5000")).start()
        socketio.run(app, host='127.0.0.1', port=5000, debug=True, use_reloader=False)
    except KeyboardInterrupt:
        print("\n\n⏹️  Shutting down...")
        sys.exit(0)
