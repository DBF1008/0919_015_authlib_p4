import contextlib
import contextvars
import logging
import uuid

#: Header used to propagate the request id across services.
REQUEST_ID_HEADER = "X-Request-ID"

_request_id_var = contextvars.ContextVar("authlib_request_id", default=None)


def generate_request_id():
    """Generate a new random request id."""
    return uuid.uuid4().hex


def get_request_id():
    """Return the request id bound to the current context, if any."""
    return _request_id_var.get()


def set_request_id(request_id):
    """Bind a request id to the current context. Returns the token
    required by :func:`reset_request_id`."""
    return _request_id_var.set(request_id)


def reset_request_id(token):
    """Restore the previous request id using a token from
    :func:`set_request_id`."""
    _request_id_var.reset(token)


@contextlib.contextmanager
def request_log_context(request_id=None):
    """Context manager that binds ``request_id`` to the current context
    for the duration of the block. If ``request_id`` is ``None``, the
    currently bound request id (if any) is kept."""
    rid = request_id or get_request_id()
    if rid is None:
        yield
        return
    token = _request_id_var.set(rid)
    try:
        yield
    finally:
        _request_id_var.reset(token)


def bind_request_id_from_headers(headers, header=REQUEST_ID_HEADER):
    """Extract the request id from HTTP headers, generating a new one
    when absent, and bind it to the current context.

    :param headers: a mapping-like object with a ``.get`` method.
    :param header: header name to look up, defaults to ``X-Request-ID``.
    :return: the bound request id.
    """
    request_id = None
    if headers is not None:
        request_id = headers.get(header)
    if not request_id:
        request_id = generate_request_id()
    set_request_id(request_id)
    return request_id


class RequestContextFilter(logging.Filter):
    """Logging filter that injects the current ``request_id`` into every
    log record, so that logs emitted anywhere in the request call chain
    can be correlated. Install it on a handler or logger::

        logging.getLogger("authlib").addFilter(RequestContextFilter())
    """

    def filter(self, record):
        if not hasattr(record, "request_id"):
            record.request_id = get_request_id() or "-"
        return True


def log_with_context(logger, level, msg, *args, **kwargs):
    """Emit a structured log record carrying the current ``request_id``
    in its ``extra`` fields."""
    extra = kwargs.pop("extra", None) or {}
    extra.setdefault("request_id", get_request_id() or "-")
    logger.log(level, msg, *args, extra=extra, **kwargs)
