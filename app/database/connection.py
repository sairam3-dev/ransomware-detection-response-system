
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database.models import Base


DATABASE_PATH = Path("data/rdrs.db")
DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)

DATABASE_URL = f"sqlite:///{DATABASE_PATH.as_posix()}"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
)


def create_database():
    """Create database tables defined by our models."""
    Base.metadata.create_all(bind=engine)


def save_file_event(event_type, file_path, destination_path=None):
    """Save one filesystem event to the database."""
    from app.database.models import FileEvent

    session = SessionLocal()

    try:
        event = FileEvent(
            event_type=event_type,
            file_path=file_path,
            destination_path=destination_path,
        )

        session.add(event)
        session.commit()

        return event.id

    except Exception:
        session.rollback()
        raise

    finally:
        session.close()


def save_process_snapshot(process_info):
    """Save one process snapshot to the database."""
    from app.database.models import ProcessSnapshot

    session = SessionLocal()

    try:
        snapshot = ProcessSnapshot(
            pid=process_info["pid"],
            name=process_info["name"],
            username=process_info.get("username"),
            cpu_percent=process_info.get("cpu_percent"),
            memory_mb=process_info.get("memory_mb"),
            timestamp=process_info["timestamp"],
        )

        session.add(snapshot)
        session.commit()
        return snapshot.id

    except Exception:
        session.rollback()
        raise

    finally:
        session.close()


def get_recent_process_snapshots(limit=100):
    """Retrieve the most recently saved process snapshots."""
    from app.database.models import ProcessSnapshot

    session = SessionLocal()

    try:
        return (
            session.query(ProcessSnapshot)
            .order_by(ProcessSnapshot.timestamp.desc())
            .limit(limit)
            .all()
        )
    finally:
        session.close()


def save_alert(title, description, threat_score, threat_level):
    """Save a security alert to the database."""
    from app.database.models import Alert

    session = SessionLocal()

    try:
        alert = Alert(
            title=title,
            description=description,
            threat_score=threat_score,
            threat_level=threat_level,
        )

        session.add(alert)
        session.commit()
        session.refresh(alert)

        return alert.id

    except Exception:
        session.rollback()
        raise

    finally:
        session.close()


def get_recent_alerts(limit=100):
    """Retrieve the most recently created security alerts."""
    from app.database.models import Alert

    session = SessionLocal()

    try:
        return (
            session.query(Alert)
            .order_by(Alert.timestamp.desc())
            .limit(limit)
            .all()
        )
    finally:
        session.close()


def update_alert_status(alert_id, new_status):
    """Update the status of an existing security alert."""
    from app.database.models import Alert

    allowed_statuses = {"open", "investigating", "resolved"}

    if new_status not in allowed_statuses:
        raise ValueError(
            f"Invalid status: {new_status}. "
            f"Choose one of {sorted(allowed_statuses)}."
        )

    session = SessionLocal()

    try:
        alert = session.get(Alert, alert_id)

        if alert is None:
            return False

        alert.status = new_status
        session.commit()
        return True

    except Exception:
        session.rollback()
        raise

    finally:
        session.close()


def save_incident(
    title,
    description,
    severity,
    alert_id=None,
):
    """Save a security incident linked to an optional alert."""
    from app.database.models import Incident

    allowed_severities = {"Low", "Medium", "High", "Critical"}

    if severity not in allowed_severities:
        raise ValueError(
            f"Invalid severity: {severity}. "
            f"Choose one of {sorted(allowed_severities)}."
        )

    session = SessionLocal()

    try:
        incident = Incident(
            alert_id=alert_id,
            title=title,
            description=description,
            severity=severity,
        )

        session.add(incident)
        session.commit()
        session.refresh(incident)

        return incident.id

    except Exception:
        session.rollback()
        raise

    finally:
        session.close()


def get_recent_incidents(limit=100):
    """Retrieve the most recently created security incidents."""
    from app.database.models import Incident

    session = SessionLocal()

    try:
        return (
            session.query(Incident)
            .order_by(Incident.timestamp.desc())
            .limit(limit)
            .all()
        )
    finally:
        session.close()


def update_incident_status(incident_id, new_status):
    """Update the status of an existing security incident."""
    from app.database.models import Incident

    allowed_statuses = {"open", "investigating", "resolved"}

    if new_status not in allowed_statuses:
        raise ValueError(
            f"Invalid status: {new_status}. "
            f"Choose one of {sorted(allowed_statuses)}."
        )

    session = SessionLocal()

    try:
        incident = session.get(Incident, incident_id)

        if incident is None:
            return False

        incident.status = new_status
        session.commit()
        return True

    except Exception:
        session.rollback()
        raise

    finally:
        session.close()
