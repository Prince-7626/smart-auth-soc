from flask import Flask, render_template
from app.analytics import total_failed_attempts, ml_anomalies, ip_activity
from app.firewall import blocked_ips

app = Flask(__name__)

@app.route("/")
def dashboard():
    try:
        with open("soc_data.json") as f:
            data = json.load(f)
    except:
        data = {
            "total_failed": 0,
            "unique_ips": 0,
            "blocked_ips": {},
            "ml_alerts": 0
        }

    return render_template(
        "dashboard.html",
        total_failed=data["total_failed"],
        unique_ips=data["unique_ips"],
        blocked=data["blocked_ips"],
        ml_alerts=data["ml_alerts"],
        blocked_ips=data["blocked_ips"]
    )

if __name__ == "__main__":
    app.run(port=5001, debug=True)
