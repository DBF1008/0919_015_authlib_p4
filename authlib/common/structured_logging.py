"""authlib.common.structured_logging.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Structured logging helpers. Loggers obtained via :func:`get_logger`
automatically carry the current ``request_id`` (see
:mod:`authlib.common.log_context`), and :func:`configure_logging` can
emit either JSON (for log aggregation) or text records.
"""

import json
import logging

from .log_context import REQUEST_ID_PLACEHOLDER
from .log_context import RequestIdFilter

#: Format used for human readable (``fmt="text"") log records.
TEXT_FORMAT = (
    "%(asctime)s %(levelname)s [request_id=%(request_id)s] %(name)s: %(message)s"
)

#: LogRecord attributes that must not be copied into the JSON payload.
_RESERVED_ATTRS = frozenset(
    {
        "name",
        "msg",
        "args",
        "levelname",
        "levelno",
        "pathname",
        "filename",
        "module",
        "exc_info",
        "exc_text",
        "stack_info",
        "lineno",
        "funcName",
        "created",
        "msecs",
        "relativeCreated",
        "thread",
        "threadName",
        "processName",
        "process",
        "taskName",
        "message",
        "asctime",
    }
)


class JsonFormatter(logging.Formatter):
    """Format log records as single-line JSON objects."""

    def format(self, record):
        payload = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": getattr(record, "request_id", REQUEST_ID_PLACEHOLDER),
        }
        for key, value in record.__dict__.items():
            if key not in _RESERVED_ATTRS and not key.startswith("_"):
                payload[key] = value
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def get_logger(name):
    """Return a logger with :class:`RequestIdFilter` attached (once)."""
    logger = logging.getLogger(name)
    if not any(isinstance(f, RequestIdFilter) for f in logger.filters):
        logger.addFilter(RequestIdFilter())
    return logger


def configure_logging(level="INFO", fmt="text", stream=None, name="authlib"):
    """Configure and return the ``authlib`` logger.

    :param level: logging level name or value, e.g. ``"DEBUG"``.
    :param fmt: ``"json"`` for structured JSON lines, ``"text"`` otherwise.
    :param stream: stream for the handler, defaults to ``sys.stderr``.
    :param name: logger name to configure.
    """
    logger = get_logger(name)
    logger.setLevel(level)
    handler = logging.StreamHandler(stream)
    if fmt == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter(TEXT_FORMAT))
    handler.addFilter(RequestIdFilter())
    logger.handlers = [handler]
    logger.propagate = False
    return logger
