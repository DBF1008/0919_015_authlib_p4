from authlib.common.health import build_health_snapshot
from authlib.common.health import inspect_token_generators
from authlib.common.metrics import TokenIssueMetrics


class _StaticGenerator:
    def __init__(self, alg=None, jwks=None):
        self.alg = alg
        self._jwks = jwks

    def get_jwks(self):
        return self._jwks


def test_inspect_token_generators_reports_key_state_without_secret():
    empty = _StaticGenerator(alg="RS256", jwks={"keys": []})
    configured = _StaticGenerator(alg="RS256", jwks={"keys": [{"kid": "k1"}]})

    states = inspect_token_generators({"default": configured, "custom": empty})

    by_name = {s["name"]: s for s in states}
    assert by_name["default"]["key_configured"] is True
    assert by_name["default"]["alg"] == "RS256"
    assert by_name["custom"]["key_configured"] is False


def test_build_health_snapshot_payload_shape():
    metrics = TokenIssueMetrics(max_size=10, component="snap")
    metrics.record(True, grant_type="client_credentials", request_id="a")
    metrics.record(False, grant_type="password", error="invalid_grant")

    snapshot = build_health_snapshot(
        grant_types=["client_credentials", "password"],
        token_generators={"default": _StaticGenerator(jwks={"keys": [{}]})},
        metrics=metrics,
        last_n=20,
        component="snap",
    )

    assert snapshot["status"] == "ok"
    assert snapshot["component"] == "snap"
    assert snapshot["grant_types"] == ["client_credentials", "password"]
    assert snapshot["token_issuance"]["success"] == 1
    assert snapshot["token_issuance"]["failure"] == 1
    assert snapshot["signers"][0]["key_configured"] is True


def test_health_snapshot_with_custom_provider():
    snapshot = build_health_snapshot(
        grant_types=[],
        key_state_provider=lambda: [{"name": "hsm", "key_configured": True}],
    )
    assert snapshot["signers"] == [{"name": "hsm", "key_configured": True}]
