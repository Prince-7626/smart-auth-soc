from collections import defaultdict
import json
import os

ip_activity = defaultdict(list)
total_failed_attempts = 0
ml_anomalies = 0

def increment_failed():
    global total_failed_attempts
    total_failed_attempts += 1

def increment_ml():
    global ml_anomalies
    ml_anomalies += 1

def save_data(blocked_ips, ml_anomalies_list):
    """Save security metrics to soc_data.json"""
    data = {
        "total_failed": total_failed_attempts,
        "unique_ips": len(ip_activity),
        "blocked_ips": blocked_ips,
        "ml_alerts": len(ml_anomalies_list)
    }
    
    soc_data_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "soc_data.json")
    with open(soc_data_path, "w") as f:
        json.dump(data, f, indent=4)
