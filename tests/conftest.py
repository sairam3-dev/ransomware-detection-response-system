
import os
import tempfile
from pathlib import Path

import pytest

TEST_DB_PATH = Path(tempfile.gettempdir()) / "rdrs_test.db"
os.environ["RDRS_DATABASE_PATH"] = str(TEST_DB_PATH)

from app.database.connection import engine
from app.database.models import Base


@pytest.fixture(autouse=True)
def reset_test_database():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
