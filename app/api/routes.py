
from fastapi import APIRouter

from app.database.connection import (
    get_recent_alerts,
    get_recent_incidents,
    update_incident_status,
)
from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from app.reports.report_generator import (
    generate_json_report,
    generate_csv_report,
)
router = APIRouter()


@router.get("/health")
def health_check():
    """Check whether the RDRS API is responding."""
    return {
        "status": "healthy",
        "application": "Ransomware Detection and Response System",
    }


@router.get("/alerts")
def list_alerts(limit: int = 50):
    """Return recent security alerts."""
    limit = max(1, min(limit, 100))

    alerts = get_recent_alerts(limit)

    return [
        {
            "id": alert.id,
            "title": alert.title,
            "description": alert.description,
            "threat_score": alert.threat_score,
            "threat_level": alert.threat_level,
            "status": alert.status,
            "timestamp": alert.timestamp.isoformat(),
        }
        for alert in alerts
    ]


@router.get("/incidents")
def list_incidents(limit: int = 50):
    """Return recent security incidents."""
    limit = max(1, min(limit, 100))

    incidents = get_recent_incidents(limit)

    return [
        {
            "id": incident.id,
            "alert_id": incident.alert_id,
            "title": incident.title,
            "description": incident.description,
            "severity": incident.severity,
            "status": incident.status,
            "timestamp": incident.timestamp.isoformat(),
        }
        for incident in incidents
    ]


from typing import Literal
from pydantic import BaseModel


class IncidentStatusUpdate(BaseModel):
    status: Literal["open", "investigating", "resolved"]


@router.patch("/incidents/{incident_id}/status")
def change_incident_status(
    incident_id: int,
    update: IncidentStatusUpdate,
):
    """Update the status of an existing incident."""
    updated = update_incident_status(
        incident_id,
        update.status,
    )

    if not updated:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    return {
        "message": "Incident status updated successfully",
        "incident_id": incident_id,
        "status": update.status,
    }



@router.get("/reports/json")
def download_json_report():
    """Generate and download the JSON security report."""
    report_path = generate_json_report()

    return FileResponse(
        path=report_path,
        media_type="application/json",
        filename="security_report.json",
    )


@router.get("/reports/csv")
def download_csv_report():
    """Generate and download the CSV alerts report."""
    report_path = generate_csv_report()

    return FileResponse(
        path=report_path,
        media_type="text/csv",
        filename="security_alerts.csv",
    )
