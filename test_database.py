
from sqlalchemy import inspect

from app.database.connection import create_database, engine


print("Creating RDRS database...")
create_database()

inspector = inspect(engine)
table_names = inspector.get_table_names()

print("Database tables:", table_names)

if "events" in table_names:
    print("SUCCESS: The events table exists.")
else:
    print("ERROR: The events table was not created.")
