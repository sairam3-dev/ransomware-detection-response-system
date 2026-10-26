
import re
from datetime import datetime, timedelta
from collections import deque
from datetime import datetime, timedelta
from app.core.config import load_config
from app.core.entropy import calculate_file_entropy
from pathlib import Path
from app.database.connection import (
    get_recent_alerts,
    get_recent_process_snapshots,
    save_alert,
    save_incident,
)

class DetectionEngine:
    """Track recent filesystem events for ransomware detection."""

    def __init__(self, window_seconds=60):
        config = load_config()

        self.known_processes = {
            Path(name).name.lower()
            for name in config.get("process_monitoring", {}).get(
                "known_processes", []
            )
        }

        self.window = timedelta(seconds=window_seconds)
        self.recent_events = deque()
        self.last_alert_fingerprint = None
        self.threat_weights = config["threat_scoring"]
        self.thresholds = config["thresholds"]

    def add_event(self, event):
        """Add an event and remove events outside the time window."""
        self.recent_events.append(event)
        self.remove_old_events()

    def remove_old_events(self):
        """Remove events that are older than the sliding window."""
        cutoff_time = datetime.now() - self.window

        while (
            self.recent_events
            and self.recent_events[0]["timestamp"] < cutoff_time
        ):
            self.recent_events.popleft()


    def count_modifications(self):
        """Count modification events in the current time window."""
        return sum(
            1
            for event in self.recent_events
            if event["event_type"] == "modified"
        )

    def count_renames(self):
        """Count move or rename events in the current time window."""
        return sum(
            1
            for event in self.recent_events
            if event["event_type"] == "moved"
        )

   
    def calculate_threat_score(
        self,
        rapid_file_changes=False,
        mass_renames=False,
        high_entropy=False,
        cpu_spike=False,
        unknown_process=False,
    ):
        """Calculate a threat score using configured weights."""
        score = 0

        if rapid_file_changes:
            score += self.threat_weights["rapid_encryption"]

        if mass_renames:
            score += self.threat_weights["mass_rename"]

        if high_entropy:
            score += self.threat_weights["high_entropy"]

        if cpu_spike:
            score += self.threat_weights["cpu_spike"]

        if unknown_process:
            score += self.threat_weights["unknown_process"]

        return min(score, 100)


    def evaluate_file_activity(self):
        """Check whether recent file activity exceeds configured thresholds."""
        modification_count = self.count_modifications()
        rename_count = self.count_renames()

        rapid_file_changes = (
            modification_count >= self.thresholds["rapid_file_changes"]
        )

        mass_renames = (
            rename_count >= self.thresholds["mass_renames"]
        )

        return {
            "modification_count": modification_count,
            "rename_count": rename_count,
            "rapid_file_changes": rapid_file_changes,
            "mass_renames": mass_renames,
        }


   
 

    def analyze_activity(self):
        """Evaluate file and process activity and calculate threat score."""
        activity = self.evaluate_file_activity()

        # Check entropy of recently modified files.
        high_entropy = False
        entropy_results = []
        checked_paths = set()

        for event in self.recent_events:
            file_path = event.get("file_path")

            if event["event_type"] != "modified" or not file_path:
                continue

            path = Path(file_path)

            if str(path) in checked_paths or not path.is_file():
                continue

            checked_paths.add(str(path))
            result = self.check_file_entropy(str(path))
            entropy_results.append(result)

            if result.get("high_entropy", False):
                high_entropy = True

       
        # Check recent process snapshots for high CPU usage
        # and unrecognized process names.
        cpu_spike = False
        unknown_process = False
        process_results = []

        for process in get_recent_process_snapshots(limit=100):
            cpu_result = self.check_cpu_spike(process.cpu_percent)
            name_result = self.check_unknown_process(process.name)

            process_results.append({
                "pid": process.pid,
                "name": process.name,
                **cpu_result,
                **name_result,
            })

            if cpu_result["cpu_spike"]:
                cpu_spike = True

            if name_result["unknown_process"]:
                unknown_process = True


        # Calculate the combined threat score.
        score = self.calculate_threat_score(
    rapid_file_changes=activity["rapid_file_changes"],
    mass_renames=activity["mass_renames"],
    high_entropy=high_entropy,
    cpu_spike=cpu_spike,
    unknown_process=False,
)

        activity["high_entropy"] = high_entropy
        activity["entropy_results"] = entropy_results
        activity["cpu_spike"] = cpu_spike
        activity["unknown_process"] = unknown_process
        activity["process_results"] = process_results
        activity["threat_score"] = score
        activity["threat_level"] = self.classify_threat_level(score)

       
        # Save an alert only if a matching alert was not created
        # during the last five minutes.
        if score >= 40:
            title = f"{activity['threat_level']} ransomware activity detected"
            description = (
                f"Detected {activity['modification_count']} file modifications, "
                f"{activity['rename_count']} file renames, "
                f"high_entropy={high_entropy}, "
                f"cpu_spike={cpu_spike}."
            )

            fingerprint = (
                activity["threat_level"],
                activity["rapid_file_changes"],
                activity["mass_renames"],
                high_entropy,
                cpu_spike,
            )

            cutoff = datetime.now() - timedelta(minutes=5)
            duplicate_found = False

           
            for alert in get_recent_alerts(limit=100):
                if alert.timestamp < cutoff:
                    break

                match = re.fullmatch(
                    r"Detected (\d+) file modifications, "
                    r"(\d+) file renames, "
                    r"high_entropy=(True|False), "
                    r"cpu_spike=(True|False)\.",
                    alert.description,
                )

                if not match:
                    continue

                modification_count = int(match.group(1))
                rename_count = int(match.group(2))

                existing_fingerprint = (
                    alert.threat_level,
                    modification_count
                    >= self.thresholds["rapid_file_changes"],
                    rename_count
                    >= self.thresholds["mass_renames"],
                    match.group(3) == "True",
                    match.group(4) == "True",
                )

                if existing_fingerprint == fingerprint:
                    duplicate_found = True
                    break


            if not duplicate_found:
                alert_id = save_alert(
                    title=title,
                    description=description,
                    threat_score=score,
                    threat_level=activity["threat_level"],
                )
                activity["alert_id"] = alert_id

                if activity["threat_level"] == "Critical":
                    activity["incident_id"] = save_incident(
                        title="Critical Ransomware Investigation",
                        description=(
                            f"Critical threat detected with score {score}. "
                            f"File modifications: "
                            f"{activity['modification_count']}; "
                            f"file renames: {activity['rename_count']}."
                        ),
                        severity="Critical",
                        alert_id=alert_id,
                    )
                else:
                    activity["incident_id"] = None
            else:
                activity["alert_id"] = None
                activity["incident_id"] = None
        else:
            activity["alert_id"] = None
            activity["incident_id"] = None

        return activity





    def classify_threat_level(self, score):
        """Classify a threat score into a severity level."""
        if score >= 70:
            return "Critical"
        elif score >= 40:
            return "Warning"
        else:
            return "Normal"


   
    def check_file_entropy(self, file_path):
        """Check whether a file has unusually high entropy."""
        try:
            entropy = calculate_file_entropy(file_path)
            threshold = self.thresholds["high_entropy"]

            return {
                "file_path": file_path,
                "entropy": entropy,
                "high_entropy": entropy >= threshold,
            }
        except (OSError, ValueError) as error:
            return {
                "file_path": file_path,
                "error": str(error),
                "high_entropy": False,
            }

    def check_cpu_spike(self, cpu_percent):
        """Check whether a valid CPU reading exceeds the configured threshold."""
        threshold = self.thresholds["cpu_spike_percent"]

        cpu_spike = (
            cpu_percent is not None
            and 0 <= cpu_percent <= 100
            and cpu_percent >= threshold
        )

        return {
            "cpu_percent": cpu_percent,
            "cpu_spike": cpu_spike,
        }

    def check_unknown_process(self, process_name):
        """Check whether a process name is in the configured allowlist."""
        normalized_name = Path(process_name or "").name.lower()

        return {
            "process_name": process_name,
            "unknown_process": normalized_name not in self.known_processes,
        }
