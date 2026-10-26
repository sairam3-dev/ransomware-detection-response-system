
import csv
import json
from pathlib import Path
from datetime import datetime

from app.database.connection import (
    get_recent_alerts,
    get_recent_incidents,
)


REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(parents=True, exist_ok=True)


def generate_json_report():
    """Export recent alerts and incidents to a JSON report."""
    alerts = get_recent_alerts(limit=100)
    incidents = get_recent_incidents(limit=100)

    report = {
        "generated_at": datetime.now().isoformat(),
        "alerts": [
            {
                "id": a.id,
                "title": a.title,
                "description": a.description,
                "threat_score": a.threat_score,
                "threat_level": a.threat_level,
                "status": a.status,
                "timestamp": a.timestamp.isoformat(),
            }
            for a in alerts
        ],
        "incidents": [
            {
                "id": i.id,
                "alert_id": i.alert_id,
                "title": i.title,
                "description": i.description,
                "severity": i.severity,
                "status": i.status,
                "timestamp": i.timestamp.isoformat(),
            }
            for i in incidents
        ],
    }

    output_path = REPORT_DIR / "security_report.json"
    output_path.write_text(
        json.dumps(report, indent=4),
        encoding="utf-8",
    )

    return output_path


def generate_csv_report():
    """Export recent alerts to a CSV file."""
    alerts = get_recent_alerts(limit=100)

    output_path = REPORT_DIR / "security_alerts.csv"

    fieldnames = [
        "id",
        "title",
        "description",
        "threat_score",
        "threat_level",
        "status",
        "timestamp",
    ]

    with output_path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()

        for alert in alerts:
            writer.writerow({
                "id": alert.id,
                "title": alert.title,
                "description": alert.description,
                "threat_score": alert.threat_score,
                "threat_level": alert.threat_level,
                "status": alert.status,
                "timestamp": alert.timestamp.isoformat(),
            })

    return output_path
