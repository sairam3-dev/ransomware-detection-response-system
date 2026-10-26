
from app.detectors.detection_engine import DetectionEngine


def test_unknown_process_score():
    engine = DetectionEngine()

    score = engine.calculate_threat_score(
        unknown_process=True
    )

    assert score == 10

def test_unknown_process_score():
    engine = DetectionEngine()

    score = engine.calculate_threat_score(
        unknown_process=True
    )

    assert score == 10

def test_combined_threat_score():
    engine = DetectionEngine()

    score = engine.calculate_threat_score(
        rapid_file_changes=True,
        mass_renames=True,
        high_entropy=True,
        cpu_spike=True,
        unknown_process=True,
    )

    assert score == 100

def test_empty_activity_has_zero_threat_score():
    engine = DetectionEngine()

    result = engine.analyze_activity()

    assert result["threat_score"] == 0

    
from datetime import datetime
from app.detectors.detection_engine import DetectionEngine


def test_rapid_file_changes_detected():
    engine = DetectionEngine()

    for i in range(21):
        engine.add_event({
            "event_type": "modified",
            "file_path": f"data/sandbox/test_file_{i}.txt",
            "timestamp": datetime.now(),
        })

    result = engine.analyze_activity()

    assert result["modification_count"] == 21
    assert result["rapid_file_changes"] is True
    assert result["threat_score"] >= 40


def test_mass_renames_detected():
    engine = DetectionEngine()

    for i in range(10):
        engine.add_event({
            "event_type": "moved",
            "file_path": f"data/sandbox/old_{i}.txt",
            "destination_path": f"data/sandbox/new_{i}.txt",
            "timestamp": datetime.now(),
        })

    result = engine.analyze_activity()

    assert result["rename_count"] == 10
    assert result["mass_renames"] is True
    assert result["threat_score"] >= 30


def test_high_entropy_file_detected(tmp_path):
    engine = DetectionEngine()

    # Create a temporary file with varied byte values.
    test_file = tmp_path / "high_entropy.bin"
    test_file.write_bytes(bytes(range(256)) * 256)

    result = engine.check_file_entropy(str(test_file))

    assert "entropy" in result
    assert result["high_entropy"] is True


def test_high_entropy_contributes_to_threat_score(tmp_path):
    engine = DetectionEngine()

    test_file = tmp_path / "high_entropy.bin"
    test_file.write_bytes(bytes(range(256)) * 256)

    engine.add_event({
        "event_type": "modified",
        "file_path": str(test_file),
        "timestamp": datetime.now(),
    })

    result = engine.analyze_activity()

    assert result["high_entropy"] is True
    assert result["threat_score"] >= 25


def test_threat_level_classification():
    engine = DetectionEngine()

    assert engine.classify_threat_level(0) == "Normal"
    assert engine.classify_threat_level(39) == "Normal"
    assert engine.classify_threat_level(40) == "Warning"
    assert engine.classify_threat_level(69) == "Warning"
    assert engine.classify_threat_level(70) == "Critical"
    assert engine.classify_threat_level(100) == "Critical"


def test_high_threat_creates_database_alert():
    from app.database.connection import get_recent_alerts

    engine = DetectionEngine()

    for i in range(20):
        engine.add_event({
            "event_type": "modified",
            "file_path": f"simulated_file_{i}.txt",
            "timestamp": datetime.now(),
        })

    result = engine.analyze_activity()

    assert result["threat_score"] >= 40
    assert result["alert_id"] is not None

    alerts = get_recent_alerts(limit=10)
    assert any(alert.id == result["alert_id"] for alert in alerts)


def test_critical_threat_creates_incident():
    from app.database.connection import (
        get_recent_incidents,
        get_recent_alerts,
    )

    engine = DetectionEngine()

    # Simulate 20 file modifications and 10 renames.
    for i in range(20):
        engine.add_event({
            "event_type": "modified",
            "file_path": f"simulated_modified_{i}.txt",
            "timestamp": datetime.now(),
        })

    for i in range(10):
        engine.add_event({
            "event_type": "moved",
            "file_path": f"simulated_old_{i}.txt",
            "destination_path": f"simulated_new_{i}.txt",
            "timestamp": datetime.now(),
        })

    result = engine.analyze_activity()

    assert result["threat_score"] >= 70
    assert result["threat_level"] == "Critical"
    assert result["alert_id"] is not None
    assert result["incident_id"] is not None

    incidents = get_recent_incidents(limit=100)
    incident = next(
        i for i in incidents
        if i.id == result["incident_id"]
    )

    assert incident.alert_id == result["alert_id"]
    assert incident.severity == "Critical"


def test_duplicate_activity_does_not_create_duplicate_alert():
    from app.database.connection import get_recent_alerts

    engine = DetectionEngine()

    for i in range(20):
        engine.add_event({
            "event_type": "modified",
            "file_path": f"duplicate_test_file_{i}.txt",
            "timestamp": datetime.now(),
        })

    first_result = engine.analyze_activity()
    second_result = engine.analyze_activity()

    assert first_result["threat_score"] >= 40
    assert first_result["alert_id"] is not None
    assert second_result["alert_id"] is None

    alerts = get_recent_alerts(limit=100)
    matching_alerts = [
        alert for alert in alerts
        if alert.id == first_result["alert_id"]
    ]

    assert len(matching_alerts) == 1


def test_duplicate_critical_activity_does_not_create_duplicate_incident():
    from app.database.connection import get_recent_incidents

    engine = DetectionEngine()

    for i in range(20):
        engine.add_event({
            "event_type": "modified",
            "file_path": f"critical_duplicate_file_{i}.txt",
            "timestamp": datetime.now(),
        })

    for i in range(10):
        engine.add_event({
            "event_type": "moved",
            "file_path": f"critical_old_{i}.txt",
            "destination_path": f"critical_new_{i}.txt",
            "timestamp": datetime.now(),
        })

    first_result = engine.analyze_activity()
    second_result = engine.analyze_activity()

    assert first_result["threat_level"] == "Critical"
    assert first_result["incident_id"] is not None
    assert second_result["incident_id"] is None

    incidents = get_recent_incidents(limit=100)
    matching_incidents = [
        incident for incident in incidents
        if incident.id == first_result["incident_id"]
    ]

    assert len(matching_incidents) == 1

