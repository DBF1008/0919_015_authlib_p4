from authlib.common.metrics import TokenIssueEvent
from authlib.common.metrics import TokenIssueMetrics
from authlib.common.metrics import get_metrics
from authlib.common.metrics import reset_metrics


def test_ring_buffer_counters_and_bounds():
    metrics = TokenIssueMetrics(max_size=5, component="test")
    for i in range(4):
        metrics.record(True, grant_type="client_credentials", request_id=f"r{i}")
    metrics.record(False, grant_type="password", error="invalid_grant")

    snapshot = metrics.snapshot()
    assert snapshot["window"] == 5
    assert snapshot["success"] == 4
    assert snapshot["failure"] == 1
    assert snapshot["recent"][-1]["error"] == "invalid_grant"

    for _ in range(10):
        metrics.record(True)
    snapshot = metrics.snapshot()
    assert snapshot["window"] == 5
    assert all(isinstance(e, TokenIssueEvent) for e in snapshot.get("events", ()))


def test_last_n_window():
    metrics = TokenIssueMetrics(max_size=100, component="test2")
    metrics.record(False)
    for _ in range(3):
        metrics.record(True)

    snapshot = metrics.snapshot(last_n=2)
    assert snapshot["window"] == 2
    assert snapshot["success"] == 2
    assert snapshot["failure"] == 0


def test_global_registry_is_singleton_per_component():
    reset_metrics()
    m1 = get_metrics("authorization_server")
    m2 = get_metrics("authorization_server")
    assert m1 is m2

    m1.record(True)
    snapshot = get_metrics("authorization_server").snapshot()
    assert snapshot["success"] == 1
    assert snapshot["window"] == 1
