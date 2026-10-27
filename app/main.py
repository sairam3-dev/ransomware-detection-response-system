
from contextlib import asynccontextmanager
from threading import Thread

from fastapi import FastAPI

from app.database.connection import create_database
from app.core.logging_config import logger
from app.api.routes import router
from app.detectors.file_monitor import start_file_monitoring


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize the database and start file monitoring."""
    create_database()

    monitor_thread = Thread(
        target=start_file_monitoring,
        name="rdrs-file-monitor",
        daemon=True,
    )
    monitor_thread.start()

    logger.info("RDRS API started in simulation-safe mode.")
    logger.info("File monitoring started in the background.")

    yield

    logger.info("RDRS API shutting down.")


app = FastAPI(
    title="Ransomware Detection and Response System",
    description="A defensive ransomware detection and incident management API.",
    version="1.0.0",
    lifespan=lifespan,
)

app.include_router(router)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8081)
