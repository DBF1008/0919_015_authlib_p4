from collections import defaultdict

from authlib.common.log_context import request_id_context


class Hookable:
    _hooks = None

    def __init__(self):
        self._hooks = defaultdict(set)

    def register_hook(self, hook_type, hook):
        self._hooks[hook_type].add(hook)

    def execute_hook(self, hook_type, *args, **kwargs):
        # When the instance carries a ``request_id`` attribute (set by
        # framework integrations), frame hook execution with it so every
        # hook runs with the current log context injected.
        request_id = getattr(self, "request_id", None)
        if request_id is not None:
            with request_id_context(request_id):
                self._run_hooks(hook_type, args, kwargs)
        else:
            self._run_hooks(hook_type, args, kwargs)

    def _run_hooks(self, hook_type, args, kwargs):
        for hook in self._hooks[hook_type]:
            hook(self, *args, **kwargs)


def hooked(func=None, before=None, after=None):
    """Execute hooks before and after the decorated method.

    The decorated method and its hooks run inside the instance log
    context: if the instance has a ``request_id`` attribute, it is bound
    for the whole execution, so hooks automatically see the current
    ``request_id``.
    """

    def decorator(func):
        before_name = before or f"before_{func.__name__}"
        after_name = after or f"after_{func.__name__}"

        def _run(self, *args, **kwargs):
            self.execute_hook(before_name, *args, **kwargs)
            result = func(self, *args, **kwargs)
            self.execute_hook(after_name, result)
            return result

        def wrapper(self, *args, **kwargs):
            request_id = getattr(self, "request_id", None)
            if request_id is not None:
                with request_id_context(request_id):
                    return _run(self, *args, **kwargs)
            return _run(self, *args, **kwargs)

        return wrapper

    # The decorator has been called without parenthesis
    if callable(func):
        return decorator(func)

    return decorator
