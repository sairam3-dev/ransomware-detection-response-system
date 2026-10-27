
import hashlib
import logging
import shutil
from pathlib import Path

from app.core.config import load_config

logger = logging.getLogger(__name__)


def quarantine_file(file_path):
    """Safely copy a suspicious file into quarantine in simulation mode."""
    config = load_config()

    if not config.get("app", {}).get("simulation_mode", True):
        logger.warning(
            "Quarantine skipped: simulation mode is disabled."
        )
        return {
            "success": False,
            "reason": "Simulation mode must be enabled.",
        }

    source = Path(file_path).resolve()

    if not source.is_file():
        logger.warning("Quarantine skipped: file unavailable: %s", source)
        return {
            "success": False,
            "reason": "Source file does not exist or is not a file.",
        }

    watch_paths = config.get("monitoring", {}).get("watch_paths", [])
    allowed_roots = [
        Path(folder).resolve()
        for folder in watch_paths
    ]

    if not any(
        source == root or root in source.parents
        for root in allowed_roots
    ):
        logger.warning(
            "Quarantine skipped: file outside watched folders: %s",
            source,
        )
        return {
            "success": False,
            "reason": "File is outside configured watch folders.",
        }

    quarantine_dir = Path("data/quarantine").resolve()
    quarantine_dir.mkdir(parents=True, exist_ok=True)

    try:
        # Hash the source to create a stable, non-overwriting filename.
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        destination = quarantine_dir / f"{digest}_{source.name}"

        if destination.exists():
            logger.info("Evidence already quarantined: %s", destination)
            return {
                "success": True,
                "source": str(source),
                "destination": str(destination),
                "already_exists": True,
            }

        # Copy only: do not delete, rename, or modify the original.
        shutil.copy2(source, destination)

        logger.info(
            "SIMULATION: evidence copied to quarantine: %s -> %s",
            source,
            destination,
        )

        return {
            "success": True,
            "source": str(source),
            "destination": str(destination),
            "already_exists": False,
        }

    except OSError:
        logger.exception("Quarantine copy failed for %s", source)
        return {
            "success": False,
            "reason": "File copy failed; check the application log.",
        }
