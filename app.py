
from flask import Flask, render_template_string, request, redirect, url_for
from datetime import datetime
import sqlite3
from pathlib import Path

import hashlib
import json
import boto3

app = Flask(__name__)
failed_attempts = {}
BASE_DIR = Path(__file__).resolve().parent
DB_NAME = BASE_DIR / "security_events.db"


TARGET_FILE = BASE_DIR / "fim_test_file.txt"
HASH_FILE = BASE_DIR / "fim_hash.json"


def check_file_integrity():
    if not TARGET_FILE.exists() or not HASH_FILE.exists():
        return "Not configured yet"

    current_hash = hashlib.sha256(
        TARGET_FILE.read_bytes()
    ).hexdigest()

    try:
        saved_data = json.loads(
            HASH_FILE.read_text(encoding="utf-8")
        )
        saved_hash = saved_data["sha256"]
    except (json.JSONDecodeError, KeyError, OSError):
        return "ERROR: Baseline hash file is invalid"

    if current_hash == saved_hash:
        return "SAFE: File unchanged"

    return "ALERT: File integrity changed!"


def init_db():
    with sqlite3.connect(DB_NAME) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                time TEXT NOT NULL,
                username TEXT NOT NULL,
                message TEXT NOT NULL,
                risk INTEGER NOT NULL
            )
        """)


def save_event(username, message, risk):
    event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with sqlite3.connect(DB_NAME) as conn:
        conn.execute(
            """INSERT INTO events (time, username, message, risk)
               VALUES (?, ?, ?, ?)""",
            (event_time, username, message, risk)
        )

    print(f"EVENT SAVED: {username} | {message} | Risk: {risk}")
    
def get_severity(risk):
    if risk >= 80:
        return "HIGH"
    elif risk >= 60:
        return "MEDIUM"
    else:
        return "LOW"

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>CloudSentinel</title>
    <style>
        body { font-family: Arial; background: #101827; color: white; padding: 30px; }
        .card { background: #1e293b; padding: 20px; margin-bottom: 20px; border-radius: 12px; }
        input, select, button { padding: 10px; margin: 5px; }
    </style>
</head>
<body>
    <h1>CloudSentinel Security Dashboard</h1>

    <div class="card">
        <h2>Simulate Login Event</h2>
        <form method="POST" action="/login">
            <input name="username" placeholder="Username" required>
            <select name="result">
                <option value="success">Successful login</option>
                <option value="failed">Failed login</option>
            </select>
            <button type="submit">Record Event</button>
        </form>
    </div>

    
<div class="card">
    <h2>Dashboard</h2>
    <p>Total events: {{ total }}</p>
    <p>High-risk events: {{ high_risk }}</p>
</div>

<div class="card">
    <h2>File Integrity Monitoring</h2>
    <p>Status: {{ fim_status }}</p>
</div>
<div class="card">
    <h2>AWS S3 File Integrity Monitoring</h2>
    <p>Status: {{ s3_fim_status }}</p>
</div>

    
<div class="card">
    <h2>Security Alert History</h2>
    {% for alert in alerts %}
        <p>
            {{ alert.time }} |
            {{ alert.username }} |
            {{ alert.message }} |
            Risk: {{ alert.risk }}/100 |
            Severity: {{ get_severity(alert.risk) }}
        </p>
    {% else %}
        <p>No high-risk alerts found.</p>
    {% endfor %}
</div>


    <div class="card">
        <h2>Recent Events</h2>
        {% for event in events %}
            <p>{{ event.time }} | {{ event.username }} |
            {{ event.message }} | Risk: {{ event.risk }}/100</p>
        {% else %}
            <p>No events recorded yet.</p>
        {% endfor %}
    </div>
</body>
</html>
"""

def check_s3_integrity():
    import hashlib
    import json
    from pathlib import Path
    import boto3
    from botocore.exceptions import ClientError

    bucket = "cloudsentinel-fim-test-2026"
    filename = "cloud_test.txt"
    baseline_file = Path("s3_baseline.json")
    alert_state_file = Path("s3_alert_state.json")

    try:
        s3 = boto3.client("s3")
        response = s3.get_object(
            Bucket=bucket,
            Key=filename
        )
        content = response["Body"].read()
        current_hash = hashlib.sha256(content).hexdigest()

        if not baseline_file.exists():
            baseline_file.write_text(
                json.dumps({
                    "bucket": bucket,
                    "file": filename,
                    "sha256": current_hash
                }, indent=4),
                encoding="utf-8"
            )
            return "Baseline created"

        baseline = json.loads(
            baseline_file.read_text(encoding="utf-8")
        )

        if (baseline.get("bucket") != bucket
                or baseline.get("file") != filename):
            return "Baseline mismatch"

        if current_hash != baseline.get("sha256"):
            last_alerted_hash = ""

            if alert_state_file.exists():
                state = json.loads(
                    alert_state_file.read_text(encoding="utf-8")
                )
                last_alerted_hash = state.get("alerted_hash", "")

           
         
            if current_hash != last_alerted_hash:
                save_event(
                    "AWS S3",
                    (
                        f"ALERT: S3 file modification detected | "
                        f"File: {filename} | "
                        f"Previous SHA-256: {baseline['sha256']} | "
                        f"Current SHA-256: {current_hash}"
                    ),
                    80
                )

                alert_state_file.write_text(
                    json.dumps({
                        "bucket": bucket,
                        "file": filename,
                        "alerted_hash": current_hash
                    }, indent=4),
                    encoding="utf-8"
                )

            return "ALERT: S3 file modification detected"

        return "SAFE: No S3 file changes detected"

    except ClientError as error:
        return "AWS error: " + error.response["Error"]["Code"]
    except (OSError, ValueError, KeyError) as error:
        return "Monitor error: " + str(error)

@app.route("/")
def dashboard():
    with sqlite3.connect(DB_NAME) as conn:
        conn.row_factory = sqlite3.Row
        total = conn.execute(
            "SELECT COUNT(*) FROM events"
        ).fetchone()[0]
        high_risk = conn.execute(
            "SELECT COUNT(*) FROM events WHERE risk >= 60"
        ).fetchone()[0]
        rows = conn.execute(
            "SELECT * FROM events ORDER BY id DESC LIMIT 100"
        ).fetchall()
        
        alerts = conn.execute(
            "SELECT * FROM events WHERE risk >= 60 ORDER BY id DESC LIMIT 100"
        ).fetchall()

    fim_status = check_file_integrity()
    s3_fim_status = check_s3_integrity()
    return render_template_string(
        HTML,
        events=rows,
        alerts=alerts,
        total=total,
        high_risk=high_risk,
        fim_status=fim_status,
        s3_fim_status=s3_fim_status,
        get_severity=get_severity
    )


@app.route("/login", methods=["POST"])
def record_login():
    username = request.form.get("username", "").strip()[:50]
    result = request.form.get("result", "")

    if not username or result not in ("success", "failed"):
        return "Invalid event", 400

    failed_attempts.setdefault(username, 0)

    if result == "failed":
        failed_attempts[username] += 1

        if failed_attempts[username] >= 3:
            risk = 80
            message = "ALERT: Repeated failed login attempts detected"
        else:
            risk = failed_attempts[username] * 20
            message = "Failed login attempt"

    else:
        failed_attempts[username] = 0
        risk = 0
        message = "Successful simulated login"

    save_event(username, message, risk)
    return redirect(url_for("dashboard"))



@app.route("/honeyfile")
def honeyfile_detection():
    username = request.args.get("user", "unknown").strip()[:50]
    save_event(
    "AWS S3",
    (
        f"ALERT: S3 file modification detected | "
        f"File: {filename} | "
        f"Previous SHA-256: {baseline['sha256']} | "
        f"Current SHA-256: {current_hash}"
    ),
    80
)
    return """
        <h2>Security Alert Triggered!</h2>
        <p>Simulated honeyfile access detected. Risk: 80/100</p>
        <a href="/">Return to Dashboard</a>
    """


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
