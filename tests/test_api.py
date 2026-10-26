
from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_health_endpoint():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_alerts_endpoint():
    response = client.get("/alerts")

    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_incidents_endpoint():
    response = client.get("/incidents")

    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_alert_limit_parameter():
    response = client.get("/alerts?limit=5")

    assert response.status_code == 200
    assert len(response.json()) <= 5


def test_json_report_endpoint():
    response = client.get("/reports/json")

    assert response.status_code == 200
    assert "generated_at" in response.json()
    assert "alerts" in response.json()
    assert "incidents" in response.json()


def test_csv_report_endpoint():
    response = client.get("/reports/csv")

    assert response.status_code == 200
    assert "text/csv" in response.headers["content-type"]


def test_update_incident_status_invalid_id():
    response = client.patch(
        "/incidents/999999/status",
        json={"status": "investigating"},
    )

    assert response.status_code == 404


def test_update_incident_status_invalid_value():
    response = client.patch(
        "/incidents/1/status",
        json={"status": "invalid_status"},
    )

    assert response.status_code == 422
