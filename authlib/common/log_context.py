"""authlib.common.log_context.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Request-scoped log context propagation based on :mod:`contextvars`.

A ``request_id`` is bound at the HTTP entry point (generated, or extracted
from the ``X-Request-ID`` header) and transparently propagated through
``authenticate_client``, ``generate_token`` and every grant
``validate_*`` / ``create_*`` call in the chain, so cross-module logs can
be correlated per request in production.
"""

import contextlib
import logging
import uuid
from contextvars import ContextVar

#: HTTP header used to propagate the request id between services.
REQUEST_ID_HEADER = "X-Request-ID"

#: Placeholder used in log records when no request id is bound.
REQUEST_ID_PLACEHOLDER = "-"

_request_id_var = ContextVar("authlib_request_id", default=None)


def get_request_id():
    """Return the request id bound to the current context, or ``None``."""
    return _request_id_var.get()


def bind_request_id(request_id):
    """Bind ``request_id`` to the current context.

    :return: a :class:`contextvars.Token` to be passed to
        :func:`reset_request_id`.
    """
    return _request_id_var.set(request_id)


def reset_request_id(token):
    """Restore the context to the state before the matching bind call."""
    _request_id_var.reset(token)


def ensure_request_id(request_id=None):
    """Bind and return a request id, generating one when missing.

    Explicit ``request_id`` wins, then the currently bound id, otherwise a
    random one is generated.

    :return: a ``(request_id, token)`` tuple.
    """
    if request_id is None:
        request_id = get_request_id()
    if request_id is None:
        request_id = uuid.uuid4().hex
    return request_id, bind_request_id(request_id)


@contextlib.contextmanager
def request_id_context(request_id):
    """Context manager binding ``request_id`` for the wrapped block."""
    token = bind_request_id(request_id)
    try:
        yield request_id
    finally:
        reset_request_id(token)


def extract_request_id(headers):
    """Extract the request id from a headers mapping.

    Works with plain dicts and framework header proxies exposing ``.get``
    (Werkzeug, Django, Starlette). Returns ``None`` when absent.
    """
    if not headers:
        return None
    get = getattr(headers, "get", None)
    if get is None:
        return None
    value = get(REQUEST_ID_HEADER)
    if value is None:
        value = get(REQUEST_ID_HEADER.lower())
    if value is None:
        return None
    value = str(value).strip()
    return value or None


class RequestIdFilter(logging.Filter):
    """Logging filter injecting the current ``request_id`` into records.

    The ``request_id`` attribute is always set so formatters can safely
    reference ``%(request_id)s`` even outside any request context.
    """

    def filter(self, record):
        record.request_id = get_request_id() or REQUEST_ID_PLACEHOLDER
        return True
