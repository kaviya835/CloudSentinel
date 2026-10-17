

import app as cloud_app

def test_dashboard_opens():
    cloud_app.app.config["TESTING"] = True
    client = cloud_app.app.test_client()

    response = client.get("/")

    assert response.status_code == 200


def test_invalid_login_event():
    cloud_app.app.config["TESTING"] = True
    client = cloud_app.app.test_client()

    response = client.post(
        "/login",
        data={"username": "", "result": "failed"}
    )

    assert response.status_code == 400

def test_repeated_failed_login_detection(monkeypatch):
    cloud_app.failed_attempts.clear()
    cloud_app.app.config["TESTING"] = True

    saved_events = []
    monkeypatch.setattr(
        cloud_app,
        "save_event",
        lambda username, message, risk: saved_events.append(
            (username, message, risk)
        )
    )

    client = cloud_app.app.test_client()

    for _ in range(3):
        response = client.post(
            "/login",
            data={"username": "testuser", "result": "failed"}
        )

    assert response.status_code == 302
    assert saved_events[-1][2] == 80
    assert "Repeated failed login attempts" in saved_events[-1][1]

def test_honeyfile_detection(monkeypatch):
    saved_events = []

    monkeypatch.setattr(
        cloud_app,
        "save_event",
        lambda username, message, risk: saved_events.append(
            (username, message, risk)
        )
    )

    client = cloud_app.app.test_client()
    response = client.get("/honeyfile?user=testuser")

    assert response.status_code == 200
    assert b"Simulated honeyfile access detected" in response.data
    assert saved_events[-1][2] == 80

def test_file_integrity_not_configured(monkeypatch):
    monkeypatch.setattr(
        cloud_app,
        "TARGET_FILE",
        cloud_app.BASE_DIR / "missing_test_file.txt"
    )
    monkeypatch.setattr(
        cloud_app,
        "HASH_FILE",
        cloud_app.BASE_DIR / "missing_test_hash.json"
    )

    assert cloud_app.check_file_integrity() == "Not configured yet"

def test_risk_severity():
    assert cloud_app.get_severity(80) == "HIGH"
    assert cloud_app.get_severity(60) == "MEDIUM"
    assert cloud_app.get_severity(20) == "LOW"
