
from fastapi import FastAPI

from app.database.connection import create_database
from app.core.logging_config import logger
from app.api.routes import router

app = FastAPI(
    title="Ransomware Detection and Response System",
    description="A defensive ransomware detection and incident management API.",
    version="1.0.0",
)

app.include_router(router)


@app.on_event("startup")
def startup():
    """Initialize the database when the API starts."""
    create_database()
    logger.info("RDRS API started in simulation-safe mode.")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8081)
