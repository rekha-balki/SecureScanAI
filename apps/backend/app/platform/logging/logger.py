import logging

from app.platform.logging.logging_config import configure_logging

# Configure logging once during import
configure_logging()


def get_logger(name: str) -> logging.Logger:
    """
    Returns a configured logger instance.
    """
    return logging.getLogger(name)