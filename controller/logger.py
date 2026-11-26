import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path


def get_controller_logger(name: str = "controller") -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    level_name = os.getenv("CONTROLLER_LOG_LEVEL", "INFO").upper()
    logger.setLevel(getattr(logging, level_name, logging.INFO))
    logger.propagate = False

    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    default_log = Path(__file__).resolve().parent / "data" / "controller.log"
    log_path = Path(os.getenv("CONTROLLER_LOG_FILE", str(default_log)))
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            log_path, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except OSError as exc:
        logger.warning("Failed to initialize file logger at %s: %s", log_path, exc)

    return logger


def list_controller_plain_logs(limit: int = 100) -> list[str]:
    default_log = Path(__file__).resolve().parent / "data" / "controller.log"
    log_path = Path(os.getenv("CONTROLLER_LOG_FILE", str(default_log)))
    if not log_path.exists():
        return []
    try:
        lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    safe_limit = max(1, min(limit, 500))
    return list(reversed(lines[-safe_limit:]))
