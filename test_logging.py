
from app.core.config import load_config
from app.core.logging_config import setup_logging

config = load_config()

logger = setup_logging(
    log_directory=config["logging"]["directory"],
    level=config["logging"]["level"],
)

logger.info("RDRS logging test started.")
logger.warning("This is a harmless test warning.")
logger.error("This is a harmless test error.")

print("Logging test completed.")
