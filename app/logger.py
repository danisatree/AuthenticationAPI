import json
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path


class JSONFormatter(logging.Formatter):
    """
    Formatter that outputs JSON strings after parsing the LogRecord.
    """

    def format(self, record):
        log_record = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "name": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "funcName": record.funcName,
            "line": record.lineno,
        }

        # Include exception info if present
        if record.exc_info:
            log_record["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_record)


def setup_logger():
    logger = logging.getLogger("AuthService")
    logger.setLevel(logging.DEBUG)

    # Console handler - Human readable for development
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)
    console_formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # File handlers - JSON formatted for observability
    logs_dir = Path("logs")
    logs_dir.mkdir(exist_ok=True)

    json_formatter = JSONFormatter()

    file_handler = RotatingFileHandler(
        logs_dir / "auth_service.log",
        maxBytes=10 * 1024 * 1024,  # 10 MB
        backupCount=5,  # Keep 5 backup files
    )
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(json_formatter)
    logger.addHandler(file_handler)

    # Error file handler - ERROR level only
    error_handler = RotatingFileHandler(
        logs_dir / "auth_service_errors.log",
        maxBytes=10 * 1024 * 1024,  # 10 MB
        backupCount=5,
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(json_formatter)
    logger.addHandler(error_handler)

    return logger


logger = setup_logger()
