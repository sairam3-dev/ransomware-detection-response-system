
from app.detectors.process_monitor import get_running_processes
from app.database.connection import create_database, save_process_snapshot
from sqlalchemy import text
from app.database.connection import engine

# Make sure the database tables exist.
create_database()

# Collect currently running processes.
processes = get_running_processes()

if processes:
    # Save the first process snapshot.
    saved_id = save_process_snapshot(processes[0])
    print("Saved process snapshot ID:", saved_id)

    # Verify that the snapshot was stored.
    with engine.connect() as connection:
        result = connection.execute(
            text("SELECT pid, name FROM processes WHERE id = :id"),
            {"id": saved_id},
        )
        print("Retrieved snapshot:", result.fetchone())
else:
    print("No running processes were found.")
