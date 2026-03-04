from collections import defaultdict

ip_activity = defaultdict(list)
total_failed_attempts = 0
ml_anomalies = 0

def increment_failed():
    global total_failed_attempts
    total_failed_attempts += 1

def increment_ml():
    global ml_anomalies
    ml_anomalies += 1
