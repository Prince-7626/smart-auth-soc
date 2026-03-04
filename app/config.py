import os

TIME_WINDOW = 60
ATTEMPT_THRESHOLD = 5

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

LOG_FILE_PATH = os.path.join(BASE_DIR, "sample_logs", "web_auth.log")
INCIDENT_LOG = os.path.join(BASE_DIR, "security_incidents.log")

GEOIP_API = "http://ip-api.com/json/"