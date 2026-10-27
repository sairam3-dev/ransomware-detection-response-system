# Ransomware Detection & Response System (RDRS)

## Architecture, Testing and Limitations

### 1. Project Overview

RDRS is a defensive security project that monitors file activity in a configured sandbox, evaluates suspicious behaviour using rule-based threat scoring, records alerts and incidents, and provides reporting through an API and dashboard.

The system operates in simulation mode. Its purpose is to demonstrate ransomware detection and response workflows safely, not to replace a production endpoint protection platform.

### 2. System Architecture

The application consists of these main components:

1. **File Monitoring:** Watchdog monitors the configured sandbox and records file creation, modification, deletion and move events.
2. **Event Storage:** SQLAlchemy and SQLite store file events, alerts and incidents.
3. **Detection Engine:** Recent file activity is evaluated against configured thresholds and assigned a threat score.
4. **Alert and Incident Management:** Suspicious activity generates alerts. Critical activity can create an incident.
5. **Quarantine Simulation:** The response module copies eligible files into quarantine while retaining the original file.
6. **FastAPI:** Provides endpoints for health checks, event information, alerts, incidents and report downloads.
7. **Streamlit Dashboard:** Provides a visual interface for reviewing security information.
8. **Reporting:** JSON and CSV exports provide records for further review.

### 3. Detection Logic

The configured detection thresholds include:

| Detection signal         |            Threshold | Score |
| ------------------------ | -------------------: | ----: |
| Rapid file modifications |            20 events |   +40 |
| Mass file renames        |            10 events |   +30 |
| High file entropy        |                  7.0 |   +25 |
| CPU spike                |                  80% |   +15 |
| Unknown process          | Configured in engine |   +10 |

The engine combines enabled signals into a threat score. The implemented alert levels include Warning and Critical. Thresholds are configurable and should be tuned to reduce false positives.

### 4. Testing and Verification

The following checks have been performed:

- Automated test suite: **23 passed, 0 failed**, with one deprecation warning.
- Docker services: API and dashboard were observed running.
- File monitoring: File events were observed being recorded in the database.
- Live alerting: A Warning alert with threat score 40 was generated and persisted.
- Report generation: JSON and CSV exports were generated and inspected.
- Quarantine integrity: A disposable test file and its quarantine copy were compared using SHA-256; the hashes matched.

These results demonstrate the tested behaviours listed above. They do not establish that every response action has passed an end-to-end live Docker test.

### 5. Limitations

- File-system polling may miss very rapid successive changes.
- Rule-based thresholds may produce false positives or miss unfamiliar ransomware behaviour.
- Entropy and CPU-based signals depend on their implementation and available measurements.
- The project is a controlled demonstration, not a production-grade endpoint detection and response solution.
- The live Critical-alert-to-quarantine workflow has not been fully verified end to end.

### 6. Safety

Testing should be limited to harmless files inside the configured sandbox. Simulation mode should remain enabled. The application should not be tested against real user documents, production systems or live ransomware.

### 7. Potential Improvements

- Improve event collection and handling of rapid file changes.
- Add more unit and integration tests for incident creation and response.
- Improve alert deduplication and false-positive handling.
- Add structured logging and clearer dashboard summaries.
- Test the complete Critical response workflow in an isolated, disposable environment.

### 8. Reproducibility

The source code, configuration, Docker Compose setup, automated tests, screenshots and generated reports are maintained in the project repository:

https://github.com/sairam3-dev/ransomware-detection-response-system
