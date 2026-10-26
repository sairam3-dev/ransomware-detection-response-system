
import psutil
from datetime import datetime
from app.database.connection import save_process_snapshot

def get_running_processes():
    """Collect basic metadata about currently running processes."""
    processes = []

    for process in psutil.process_iter(
        ["pid", "name", "username", "cpu_percent", "memory_info"]
    ):
        try:
            process_info = process.info
            memory_info = process_info.get("memory_info")

            processes.append({
                "pid": process_info["pid"],
                "name": process_info["name"] or "Unknown",
                "username": process_info["username"],
                "cpu_percent": process_info["cpu_percent"],
                "memory_mb": (
                    round(memory_info.rss / (1024 * 1024), 2)
                    if memory_info else None
                ),
                "timestamp": datetime.now(),
            })

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return processes


def collect_and_save_processes():
    """Collect running processes and save their snapshots to SQLite."""
    processes = get_running_processes()
    saved_count = 0

    for process_info in processes:
        try:
            save_process_snapshot(process_info)
            saved_count += 1
        except Exception as error:
            print(
                f"Could not save process PID "
                f"{process_info['pid']}: {error}"
            )

    return saved_count

