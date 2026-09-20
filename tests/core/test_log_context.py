import logging

import pytest

from authlib.common.log_context import RequestContextFilter
from authlib.common.log_context import bind_request_id_from_headers
from authlib.common.log_context import get_request_id
from authlib.common.log_context import log_with_context
from authlib.common.log_context import request_log_context
from authlib.common.log_context import reset_request_id
from authlib.common.log_context import set_request_id
from authlib.common.metrics import TokenMetrics
from authlib.oauth2.rfc6749.authorization_server import AuthorizationServer
from authlib.oauth2.rfc6749.grants import ClientCredentialsGrant
from authlib.oauth2.rfc6749.hooks import Hookable
from authlib.oauth2.rfc6749.hooks import hooked
from authlib.oauth2.rfc6750 import BearerTokenGenerator


@pytest.fixture(autouse=True)
def clean_request_context():
    token = set_request_id(None)
    yield
    reset_request_id(token)


def test_set_get_reset_request_id():
    assert get_request_id() is None
    token = set_request_id("req-1")
    assert get_request_id() == "req-1"
    reset_request_id(token)
    assert get_request_id() is None


def test_request_log_context_nesting():
    with request_log_context("outer"):
        assert get_request_id() == "outer"
        with request_log_context("inner"):
            assert get_request_id() == "inner"
        assert get_request_id() == "outer"
    assert get_request_id() is None


def test_request_log_context_keeps_current():
    with request_log_context("current"):
        with request_log_context():
            assert get_request_id() == "current"


def test_bind_request_id_from_headers():
    request_id = bind_request_id_from_headers({"X-Request-ID": "from-header"})
    assert request_id == "from-header"
    assert get_request_id() == "from-header"


def test_bind_request_id_generates_when_missing():
    token = set_request_id("previous")
    reset_request_id(token)
    request_id = bind_request_id_from_headers({})
    assert request_id
    assert len(request_id) == 32
    assert get_request_id() == request_id


def test_request_context_filter():
    record = logging.LogRecord("test", logging.INFO, __file__, 1, "msg", None, None)
    RequestContextFilter().filter(record)
    assert record.request_id == "-"

    with request_log_context("req-filter"):
        record = logging.LogRecord("test", logging.INFO, __file__, 1, "msg", None, None)
        RequestContextFilter().filter(record)
        assert record.request_id == "req-filter"


def test_log_with_context(caplog):
    logger = logging.getLogger("authlib.test_log_context")
    with caplog.at_level(logging.DEBUG, logger=logger.name):
        with request_log_context("req-log"):
            log_with_context(logger, logging.DEBUG, "hello %s", "world")
    assert caplog.records[-1].request_id == "req-log"
    assert caplog.records[-1].getMessage() == "hello world"


def test_hooked_injects_request_id_into_hooks():
    seen = {}

    class Server(Hookable):
        @hooked
        def process(self):
            return get_request_id()

    server = Server()
    server.register_hook(
        "before_process",
        lambda self_: seen.setdefault("before", get_request_id()),
    )
    server.register_hook(
        "after_process",
        lambda self_, result: seen.setdefault("after", get_request_id()),
    )

    with request_log_context("req-hook"):
        result = server.process()

    assert result == "req-hook"
    assert seen["before"] == "req-hook"
    assert seen["after"] == "req-hook"


def test_hooked_without_request_id():
    class Server(Hookable):
        @hooked
        def process(self):
            return get_request_id()

    assert Server().process() is None


def test_token_metrics_counts_and_recent():
    metrics = TokenMetrics(max_events=5)
    metrics.record_success("client_credentials")
    metrics.record_failure("password", error="invalid_grant")
    metrics.record_failure("password", error="invalid_client")

    snapshot = metrics.snapshot()
    assert snapshot["success"] == 1
    assert snapshot["failure"] == 2
    assert snapshot["total"] == 3
    assert len(snapshot["recent"]) == 3
    assert snapshot["recent"][1]["error"] == "invalid_grant"

    snapshot = metrics.snapshot(last_n=2)
    assert len(snapshot["recent"]) == 2
    assert snapshot["recent"][-1]["error"] == "invalid_client"


def test_token_metrics_event_carries_request_id():
    metrics = TokenMetrics()
    with request_log_context("req-metrics"):
        metrics.record_success("client_credentials")
    assert metrics.snapshot()["recent"][0]["request_id"] == "req-metrics"


def test_token_metrics_ring_buffer():
    metrics = TokenMetrics(max_events=3)
    for _ in range(5):
        metrics.record_success("client_credentials")
    snapshot = metrics.snapshot()
    assert snapshot["success"] == 5
    assert len(snapshot["recent"]) == 3


def test_server_health_status():
    server = AuthorizationServer()
    server.register_token_generator(
        "default", BearerTokenGenerator(lambda **kwargs: "token")
    )
    server.register_grant(ClientCredentialsGrant)

    status = server.get_health_status()
    assert status["status"] == "ok"
    assert status["token_signer"]["default"]["configured"] is True
    assert status["token_signer"]["default"]["type"] == "BearerTokenGenerator"
    assert status["token_signer"]["default"]["access_token_generator"] == "configured"
    assert status["token_signer"]["default"]["refresh_token_generator"] == "disabled"
    assert status["grants"]["token"] == [
        {"name": "ClientCredentialsGrant", "grant_type": "client_credentials"}
    ]
    assert status["grants"]["authorization"] == []
    assert status["token_issuance"]["success"] == 0
    assert status["token_issuance"]["failure"] == 0
