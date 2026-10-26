
from pathlib import Path

from loguru import logger


def setup_logging(log_directory="logs", level="INFO"):
    """Configure RDRS logging to a file and the console."""
    log_path = Path(log_directory)
    log_path.mkdir(parents=True, exist_ok=True)

    logger.remove()

    # Show log messages in the terminal.
    logger.add(
        sink=lambda message: print(message, end=""),
        level=level,
    )

    # Save log messages to a rotating file.
    logger.add(
        str(log_path / "system.log"),
        level=level,
        rotation="1 MB",
        retention=3,
        encoding="utf-8",
    )

    return logger
