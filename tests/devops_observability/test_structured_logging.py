import io
import json

from authlib.common.log_context import RequestIdFilter
from authlib.common.log_context import request_id_context
from authlib.common.structured_logging import JsonFormatter
from authlib.common.structured_logging import configure_logging
from authlib.common.structured_logging import get_logger


def test_json_formatter_contains_request_id():
    stream = io.StringIO()
    logger = configure_logging("DEBUG", fmt="json", stream=stream)
    with request_id_context("json-rid"):
        logger.info(
            "hello",
            extra={"event": "test_event", "grant_type": "client_credentials"},
        )

    line = stream.getvalue().strip()
    payload = json.loads(line)
    assert isinstance(logger.handlers[0].formatter, JsonFormatter)
    assert payload["request_id"] == "json-rid"
    assert payload["event"] == "test_event"
    assert payload["grant_type"] == "client_credentials"
    assert payload["message"] == "hello"
    assert payload["level"] == "INFO"


def test_text_formatter_includes_request_id():
    stream = io.StringIO()
    logger = configure_logging("DEBUG", fmt="text", stream=stream)
    with request_id_context("text-rid"):
        logger.warning("careful")

    assert "text-rid" in stream.getvalue()
    assert "careful" in stream.getvalue()


def test_get_logger_attaches_filter_once():
    logger = get_logger("authlib.some.module")
    before = sum(isinstance(f, RequestIdFilter) for f in logger.filters)
    logger = get_logger("authlib.some.module")
    after = sum(isinstance(f, RequestIdFilter) for f in logger.filters)
    assert before == 1
    assert after == 1
