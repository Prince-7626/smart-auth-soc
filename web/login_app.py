import os
from flask import Flask, render_template, request
from datetime import datetime

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_FILE = os.path.join(BASE_DIR, "sample_logs", "web_auth.log")

os.makedirs(os.path.join(BASE_DIR, "sample_logs"), exist_ok=True)

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        ip = request.remote_addr
        timestamp = datetime.now().strftime("%b %d %H:%M:%S")

        log_entry = f"{timestamp} server sshd[9999]: Failed password for {username} from {ip}\n"

        with open(LOG_FILE, "a") as f:
            f.write(log_entry)

        return "Login Failed"

    return render_template("login.html")

if __name__ == "__main__":
    app.run(port=5000, debug=True)