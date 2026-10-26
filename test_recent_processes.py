
from app.database.connection import get_recent_process_snapshots

snapshots = get_recent_process_snapshots(limit=5)

print("Recent process snapshots retrieved:", len(snapshots))

for snapshot in snapshots:
    print(
        "PID:", snapshot.pid,
        "| Name:", snapshot.name,
        "| CPU:", snapshot.cpu_percent,
        "| Memory MB:", snapshot.memory_mb,
    )

