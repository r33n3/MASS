"""Structured logging configuration using structlog.

Sets up structlog to wrap Python's stdlib logging so that all existing
``logging.getLogger()`` calls automatically produce structured JSON
output in production and human-readable colored output in development.

Call ``setup_logging()`` once during application startup.
"""

import logging
import sys

import structlog

from mass.core.config import get_settings


def setup_logging() -> None:
    """Configure structured logging for the entire application."""
    settings = get_settings()
    is_dev = settings.is_development
    log_level = getattr(logging, settings.log_level, logging.INFO)

    # Shared processors for both structlog and stdlib
    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
    ]

    if is_dev:
        # Development: human-readable colored output
        renderer = structlog.dev.ConsoleRenderer()
    else:
        # Production/staging: JSON output
        shared_processors.append(structlog.processors.format_exc_info)
        renderer = structlog.processors.JSONRenderer()

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # Configure stdlib logging to use structlog formatting.
    # ExtraAdder extracts `extra={...}` from stdlib LogRecords.
    formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ExtraAdder(),
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    # Apply to root logger
    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(log_level)

    # Quiet noisy third-party loggers
    for noisy in ("httpx", "httpcore", "uvicorn.access", "watchfiles"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
