import logging

from authlib.common.log_context import REQUEST_ID_HEADER
from authlib.common.log_context import RequestIdFilter
from authlib.common.log_context import bind_request_id
from authlib.common.log_context import ensure_request_id
from authlib.common.log_context import extract_request_id
from authlib.common.log_context import get_request_id
from authlib.common.log_context import request_id_context
from authlib.common.log_context import reset_request_id


def test_context_var_propagates_and_resets():
    assert get_request_id() is None
    token = bind_request_id("req-123")
    try:
        assert get_request_id() == "req-123"
    finally:
        reset_request_id(token)
    assert get_request_id() is None


def test_ensure_request_id_generates_when_missing():
    rid, token = ensure_request_id(None)
    try:
        assert rid and get_request_id() == rid
    finally:
        reset_request_id(token)
    assert get_request_id() is None


def test_nested_context_restores_outer_value():
    outer = bind_request_id("outer")
    try:
        with request_id_context("inner"):
            assert get_request_id() == "inner"
        assert get_request_id() == "outer"
    finally:
        reset_request_id(outer)


def test_extract_request_id_from_dict_and_header_proxies():
    assert extract_request_id({REQUEST_ID_HEADER: "abc"}) == "abc"

    class Proxy:
        def __init__(self, data):
            self._data = data

        def get(self, key):
            return self._data.get(key)

    assert extract_request_id(Proxy({"x-request-id": "xyz"})) == "xyz"


def test_request_id_filter_injects_record_attribute():
    record = logging.LogRecord("t", logging.INFO, __file__, 1, "hi", (), None)
    RequestIdFilter().filter(record)
    assert record.request_id == "-"

    token = bind_request_id("req-123")
    try:
        filtered = logging.LogRecord("t", logging.INFO, __file__, 1, "hi", (), None)
        RequestIdFilter().filter(filtered)
        assert filtered.request_id == "req-123"
    finally:
        reset_request_id(token)
