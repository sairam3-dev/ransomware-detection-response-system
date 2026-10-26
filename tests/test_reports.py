
import json

from app.reports.report_generator import (
    generate_json_report,
    generate_csv_report,
)


def test_json_report_is_generated():
    report_path = generate_json_report()

    assert report_path.exists()

    report = json.loads(
        report_path.read_text(encoding="utf-8")
    )

    assert "generated_at" in report
    assert "alerts" in report
    assert "incidents" in report


def test_csv_report_is_generated():
    report_path = generate_csv_report()

    assert report_path.exists()

    content = report_path.read_text(encoding="utf-8")

    assert "threat_score" in content
    assert "threat_level" in content
