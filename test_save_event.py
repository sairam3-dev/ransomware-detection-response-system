
from sqlalchemy import select

from app.database.connection import SessionLocal, save_file_event
from app.database.models import FileEvent


print("Saving a sample file event...")

event_id = save_file_event(
    event_type="created",
    file_path="data/sandbox/database_test.txt",
)

print("Saved event ID:", event_id)

session = SessionLocal()

try:
    statement = select(FileEvent).where(FileEvent.id == event_id)
    saved_event = session.scalars(statement).first()

    if saved_event is not None:
        print("SUCCESS: Event retrieved from database.")
        print("Event type:", saved_event.event_type)
        print("File path:", saved_event.file_path)
        print("Timestamp:", saved_event.timestamp)
    else:
        print("ERROR: Event was not found.")
finally:
    session.close()
