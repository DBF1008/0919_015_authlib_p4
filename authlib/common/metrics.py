"""authlib.common.metrics.
~~~~~~~~~~~~~~~~~~~~~~~~~~

In-memory token issuance metrics. Each authorization server records
success/failure events into a bounded ring buffer; the most recent N
events can be inspected through :func:`TokenIssueMetrics.snapshot` and
exposed on health check endpoints.
"""

import threading
import time
from collections import deque

#: Default number of token issuance events kept per component.
DEFAULT_MAX_SIZE = 100


class TokenIssueEvent:
    """A single token issuance attempt."""

    __slots__ = (
        "success",
        "grant_type",
        "request_id",
        "error",
        "component",
        "timestamp",
    )

    def __init__(
        self,
        success,
        grant_type=None,
        request_id=None,
        error=None,
        component=None,
        timestamp=None,
    ):
        self.success = bool(success)
        self.grant_type = grant_type
        self.request_id = request_id
        self.error = error
        self.component = component
        self.timestamp = timestamp if timestamp is not None else time.time()

    def to_dict(self):
        return {
            "success": self.success,
            "grant_type": self.grant_type,
            "request_id": self.request_id,
            "error": self.error,
            "component": self.component,
            "timestamp": self.timestamp,
        }


class TokenIssueMetrics:
    """Bounded ring buffer of :class:`TokenIssueEvent` with counters."""

    def __init__(self, max_size=DEFAULT_MAX_SIZE, component="authorization_server"):
        self.max_size = max_size
        self.component = component
        self._events = deque(maxlen=max_size)
        self._lock = threading.Lock()

    def record(self, success, grant_type=None, request_id=None, error=None):
        """Record a token issuance attempt."""
        event = TokenIssueEvent(
            success,
            grant_type=grant_type,
            request_id=request_id,
            error=error,
            component=self.component,
        )
        with self._lock:
            self._events.append(event)
        return event

    def snapshot(self, last_n=None):
        """Return counters and events for the most recent ``last_n`` events.

        When ``last_n`` is omitted, the whole retained window is used.
        """
        with self._lock:
            events = list(self._events)
        if last_n is not None:
            events = events[-last_n:] if last_n >= 0 else []
        success = sum(1 for e in events if e.success)
        failure = len(events) - success
        return {
            "component": self.component,
            "window": len(events),
            "success": success,
            "failure": failure,
            "events": events,
            "recent": [e.to_dict() for e in events],
        }


_registry = {}
_registry_lock = threading.Lock()


def get_metrics(component="authorization_server"):
    """Return the process-wide metrics singleton for ``component``."""
    with _registry_lock:
        metrics = _registry.get(component)
        if metrics is None:
            metrics = _registry[component] = TokenIssueMetrics(component=component)
        return metrics


def reset_metrics():
    """Drop all registered component metrics (mainly for tests)."""
    with _registry_lock:
        _registry.clear()
