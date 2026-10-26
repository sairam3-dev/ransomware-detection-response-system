
from datetime import datetime, timedelta

from app.detectors.detection_engine import DetectionEngine


engine = DetectionEngine(window_seconds=60)

now = datetime.now()

event_1 = {
    "event_type": "modified",
    "file_path": "data/sandbox/file1.txt",
    "timestamp": now - timedelta(seconds=70),
}

event_2 = {
    "event_type": "modified",
    "file_path": "data/sandbox/file2.txt",
    "timestamp": now - timedelta(seconds=10),
}

engine.add_event(event_1)
engine.add_event(event_2)

print("Events remaining:", len(engine.recent_events))
print("Remaining file:", engine.recent_events[0]["file_path"])


print("Modification count:", engine.count_modifications())
print("Rename count:", engine.count_renames())


print(
    "Score — no signals:",
    engine.calculate_threat_score(),
)

print(
    "Score — rapid changes:",
    engine.calculate_threat_score(rapid_file_changes=True),
)

print(
    "Score — rapid changes and renames:",
    engine.calculate_threat_score(
        rapid_file_changes=True,
        mass_renames=True,
    ),
)

print(
    "Score — all signals:",
    engine.calculate_threat_score(
        rapid_file_changes=True,
        mass_renames=True,
        high_entropy=True,
        cpu_spike=True,
        unknown_process=True,
    ),
)


print("Activity evaluation:", engine.evaluate_file_activity())

print("Complete activity analysis:", engine.analyze_activity())

# Simulate rapid file modifications
for i in range(20):
    engine.add_event({
        "event_type": "modified",
        "file_path": f"data/sandbox/test_file_{i}.txt",
        "timestamp": datetime.now(),
    })

print("Activity after simulated rapid changes:", engine.analyze_activity())

# Simulate mass file renaming
for i in range(10):
    engine.add_event({
        "event_type": "moved",
        "file_path": f"data/sandbox/test_file_{i}.txt",
        "destination_path": f"data/sandbox/test_file_{i}.locked",
        "timestamp": datetime.now(),
    })

print("Activity after simulated mass renaming:", engine.analyze_activity())


print("Level for score 0:", engine.classify_threat_level(0))
print("Level for score 40:", engine.classify_threat_level(40))
print("Level for score 70:", engine.classify_threat_level(70))

# Test entropy detection using an existing sample file
entropy_result = engine.check_file_entropy("test_entropy_manual.py")
print("Entropy test result:", entropy_result)


from pathlib import Path

# Create a temporary high-entropy sample file.
sample_path = Path("data/sandbox/entropy_test.bin")
sample_path.parent.mkdir(parents=True, exist_ok=True)

with sample_path.open("wb") as sample_file:
    sample_file.write(bytes(range(256)) * 256)

# Test the entropy detector.
print("High-entropy file test:", engine.check_file_entropy(str(sample_path)))

# Test the threat score for a high-entropy signal alone.
print(
    "High-entropy-only score:",
    engine.calculate_threat_score(high_entropy=True)
)

# Test high-entropy detection through the complete analysis workflow
engine.add_event({
    "event_type": "modified",
    "file_path": str(sample_path),
    "timestamp": datetime.now(),
})

print("Full entropy analysis:", engine.analyze_activity())

# Test CPU-spike detection using simulated values
print("CPU at 50%:", engine.check_cpu_spike(50))
print("CPU at 80%:", engine.check_cpu_spike(80))
print("CPU at 95%:", engine.check_cpu_spike(95))
print("CPU unavailable:", engine.check_cpu_spike(None))


# Test unknown-process detection
engine = DetectionEngine()

print(
    "Known process test:",
    engine.check_unknown_process("python.exe")
)

print(
    "Unknown process test:",
    engine.check_unknown_process("suspicious_test.exe")
)


def test_unknown_process_score():
    engine = DetectionEngine()

    score = engine.calculate_threat_score(
        unknown_process=True
    )

    assert score == 10

