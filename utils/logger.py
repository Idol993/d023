import logging
import os
from logging.handlers import RotatingFileHandler


def setup_logger(name: str, config: dict) -> logging.Logger:
    logger = logging.getLogger(name)
    level = getattr(logging, config.get("level", "INFO").upper(), logging.INFO)
    logger.setLevel(level)

    log_format = config.get(
        "format", "%(asctime)s [%(levelname)s] %(name)s - %(message)s"
    )
    formatter = logging.Formatter(log_format)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    log_file = config.get("file")
    if log_file:
        log_dir = os.path.dirname(log_file)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        max_size = config.get("max_size_mb", 50) * 1024 * 1024
        backup_count = config.get("backup_count", 10)
        file_handler = RotatingFileHandler(
            log_file, maxBytes=max_size, backupCount=backup_count, encoding="utf-8"
        )
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger
