
from sqlalchemy import inspect
from app.database.connection import create_database, engine

create_database()

inspector = inspect(engine)
tables = inspector.get_table_names()

print("Database tables:", tables)
print("Processes table exists:", "processes" in tables)
