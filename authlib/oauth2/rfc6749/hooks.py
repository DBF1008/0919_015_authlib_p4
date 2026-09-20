import functools
import logging
from collections import defaultdict

from authlib.common.log_context import get_request_id
from authlib.common.log_context import log_with_context
from authlib.common.log_context import request_log_context

log = logging.getLogger(__name__)


class Hookable:
    _hooks = None

    def __init__(self):
        self._hooks = defaultdict(set)

    def register_hook(self, hook_type, hook):
        self._hooks[hook_type].add(hook)

    def execute_hook(self, hook_type, *args, **kwargs):
        request_id = get_request_id()
        for hook in self._hooks[hook_type]:
            with request_log_context(request_id):
                log_with_context(
                    log,
                    logging.DEBUG,
                    "executing hook %s",
                    hook_type,
                    extra={"hook_type": hook_type},
                )
                hook(self, *args, **kwargs)


def hooked(func=None, before=None, after=None):
    """Execute hooks before and after the decorated method.

    The decorator injects the current logging context (including the
    ``request_id`` bound via :mod:`authlib.common.log_context`) so that
    every hook execution automatically carries the current request id.
    """

    def decorator(func):
        before_name = before or f"before_{func.__name__}"
        after_name = after or f"after_{func.__name__}"

        @functools.wraps(func)
        def wrapper(self, *args, **kwargs):
            request_id = get_request_id()
            with request_log_context(request_id):
                self.execute_hook(before_name, *args, **kwargs)
                result = func(self, *args, **kwargs)
                self.execute_hook(after_name, result)
            return result

        return wrapper

    # The decorator has been called without parenthesis
    if callable(func):
        return decorator(func)

    return decorator
