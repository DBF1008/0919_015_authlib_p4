import time
from collections import deque

from .log_context import get_request_id


class TokenMetrics:
    """In-memory metrics for token issuance/exchange operations.

    Tracks cumulative success/failure counters and keeps the most recent
    ``max_events`` events in a ring buffer for health-check reporting.
    """

    def __init__(self, max_events=100):
        self.max_events = max_events
        self.success_count = 0
        self.failure_count = 0
        self._events = deque(maxlen=max_events)

    def record_success(self, grant_type=None, **extra):
        """Record a successful token issuance/exchange."""
        self.success_count += 1
        self._append("success", grant_type, extra)

    def record_failure(self, grant_type=None, error=None, **extra):
        """Record a failed token issuance/exchange."""
        self.failure_count += 1
        if error is not None:
            extra["error"] = error
        self._append("failure", grant_type, extra)

    def _append(self, outcome, grant_type, extra):
        event = {
            "outcome": outcome,
            "grant_type": grant_type,
            "request_id": get_request_id(),
            "timestamp": time.time(),
        }
        event.update(extra)
        self._events.append(event)

    @property
    def total(self):
        return self.success_count + self.failure_count

    def snapshot(self, last_n=None):
        """Return a JSON-serializable snapshot of the metrics.

        :param last_n: limit the number of recent events included.
        """
        events = list(self._events)
        if last_n is not None:
            events = events[-last_n:] if last_n >= 0 else []
        return {
            "success": self.success_count,
            "failure": self.failure_count,
            "total": self.total,
            "recent": events,
        }
