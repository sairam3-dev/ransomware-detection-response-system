# Ransomware Detection & Response System (RDRS)

## Project Overview

The Ransomware Detection & Response System (RDRS) is a defensive cybersecurity project designed to monitor file activity, identify suspicious behavior, calculate threat scores, and support incident investigation.

The system runs in simulation-safe mode and uses a controlled sandbox for file-monitoring tests.

## Objectives

- Monitor file creation, modification, deletion, and rename events.
- Detect rapid file modifications and mass renaming.
- Analyze file entropy to identify potentially suspicious changes.
- Collect process information and check CPU usage.
- Calculate a threat score from 0 to 100.
- Generate Warning and Critical security alerts.
- Create incidents for Critical detections.
- Store events, alerts, processes, and incidents in an SQLite database.
- Provide API endpoints and a dashboard for monitoring.
- Generate JSON and CSV reports.

## Technology Stack

- Python
- FastAPI
- SQLite
- SQLAlchemy
- Streamlit
- Watchdog
- Pytest
- PowerShell
- Windows 11

## Detection Logic

The detection engine assigns scores to suspicious indicators:

| Indicator          | Score |
| ------------------ | ----: |
| Rapid file changes |    40 |
| Mass file renames  |    30 |
| High file entropy  |    25 |
| High CPU usage     |    15 |
| Unknown process    |    10 |

The maximum threat score is capped at 100.

### Threat Levels

- **Normal:** Score below 40
- **Warning:** Score from 40 to 69
- **Critical:** Score of 70 or higher

The current detection engine evaluates unknown processes but does not add their score to the combined threat score.

## Main Features

### File Monitoring

Watches the configured sandbox directory and records file activity.

### Threat Detection

Evaluates recent file events using a sliding time window and configured thresholds.

### Alert and Incident Management

Stores alerts in SQLite and creates investigation incidents for Critical detections.

### REST API

Provides endpoints to check system health, retrieve alerts and incidents, update incident status, and access reports.

### Dashboard

Provides a visual interface for reviewing security information.

### Reporting

Supports JSON and CSV security reports.

## Project Structure

```text
rdrs/
├── app/
│   ├── api/
│   ├── core/
│   ├── database/
│   ├── detectors/
│   ├── dashboard/
│   ├── reports/
│   └── main.py
├── tests/
├── data/
│   └── sandbox/
├── logs/
├── reports/
├── config.yaml
├── requirements.txt
└── README.md
```

## Setup

1. Install Python and create a virtual environment.
2. Activate the virtual environment.
3. Install the packages listed in `requirements.txt`.
4. Review `config.yaml` and confirm that monitoring is restricted to the test sandbox.

Install dependencies:

```powershell
pip install -r requirements.txt
```

## Run the API

From the project root, activate the virtual environment and run:

```powershell
python -m app.main
```

Open the API documentation in your browser:

http://127.0.0.1:8081/docs

## Run the File Monitor

Open another terminal in the project root and run:

```powershell
python -m app.detectors.file_monitor
```

Use only harmless test files in the configured sandbox.

## Run the Dashboard

Open another terminal and run:

```powershell
python -m streamlit run app/dashboard/dashboard.py
```

The dashboard normally opens at:

http://localhost:8501

## Run Tests

Run the complete test suite:

```powershell
python -m pytest -v
```

The current test suite contains 22 tests covering the API, detection engine, alert and incident behavior, and report generation.

## Safety

This project is intended for defensive monitoring and controlled testing. It does not need to encrypt real files to test its detection logic. Keep monitoring paths restricted to the sandbox and back up important project data.

## Project Status

The API, detection engine, file monitoring integration, dashboard, reporting features, and existing automated tests have been implemented.

Further improvements include persistent duplicate-alert suppression across monitor restarts, expanded integration testing, and additional documentation.

## Disclaimer

This project is developed for educational and defensive cybersecurity purposes.
