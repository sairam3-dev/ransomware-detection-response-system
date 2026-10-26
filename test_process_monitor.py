
from app.database.connection import create_database
from app.detectors.process_monitor import collect_and_save_processes

create_database()

saved_count = collect_and_save_processes()

print("Process snapshots saved:", saved_count)
