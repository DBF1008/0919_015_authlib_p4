"""End-to-end Flask checks: request id propagation, /health and counters."""

import base64

import pytest

flask = pytest.importorskip("flask")
from flask import Flask  # noqa: E402

from authlib.common.log_context import get_request_id  # noqa: E402
from authlib.common.metrics import reset_metrics  # noqa: E402
from authlib.integrations.flask_oauth2 import AuthorizationServer  # noqa: E402
from authlib.oauth2.rfc6749.grants import ClientCredentialsGrant  # noqa: E402


class Client:
    def __init__(self, client_id, client_secret):
        self.client_id = client_id
        self.client_secret = client_secret

    def check_client_secret(self, client_secret):
        return client_secret == self.client_secret

    def check_endpoint_auth_method(self, method, endpoint):
        return True

    def check_grant_type(self, grant_type):
        return grant_type == "client_credentials"

    def check_response_type(self, response_type):
        return True

    def get_allowed_scope(self, scope=None):
        return "profile"


CLIENTS = {"id-1": Client("id-1", "secret-1")}


def _basic_auth(client_id, client_secret):
    raw = f"{client_id}:{client_secret}".encode()
    return "Basic " + base64.b64encode(raw).decode()


@pytest.fixture
def client():
    reset_metrics()
    app = Flask(__name__)
    app.config.update(
        {
            "OAUTH2_SCOPES_SUPPORTED": ["profile"],
            "TESTING": True,
        }
    )
    server = AuthorizationServer()
    server.init_app(
        app,
        query_client=lambda client_id: CLIENTS.get(client_id),
        save_token=lambda *args, **kwargs: None,
    )
    server.register_grant(ClientCredentialsGrant)

    @app.route("/oauth/token", methods=["POST"])
    def issue():
        return server.create_token_response()

    return app.test_client()


def test_health_endpoint_reports_state_without_auth(client):
    response = client.get("/health")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "ok"
    assert payload["component"] == "flask_authorization_server"
    assert "client_credentials" in payload["grant_types"]
    assert any(s["name"] == "default" for s in payload["signers"])
    assert payload["token_issuance"]["success"] == 0
    assert payload["token_issuance"]["failure"] == 0


def test_health_does_not_require_grant_or_token(client):
    response = client.post("/oauth/token", data={"grant_type": "client_credentials"})
    assert response.status_code in (400, 401)

    payload = client.get("/health").get_json()
    assert payload["status"] == "ok"
    assert "signers" in payload and "grant_types" in payload


def test_inbound_request_id_is_echoed(client):
    response = client.get("/health", headers={"X-Request-ID": "flask-rid-1"})
    assert response.headers["X-Request-ID"] == "flask-rid-1"


def test_request_id_propagates_and_metrics_recorded_on_success(client):
    response = client.post(
        "/oauth/token",
        data={"grant_type": "client_credentials", "scope": "profile"},
        headers={
            "Authorization": _basic_auth("id-1", "secret-1"),
            "X-Request-ID": "flask-success-rid",
        },
    )
    assert response.status_code == 200
    assert response.headers["X-Request-ID"] == "flask-success-rid"
    assert "access_token" in response.get_json()

    payload = client.get("/health").get_json()
    assert payload["token_issuance"]["success"] == 1
    assert payload["token_issuance"]["recent"][0]["request_id"] == "flask-success-rid"


def test_failed_issuance_records_failure_counter(client):
    response = client.post(
        "/oauth/token",
        data={"grant_type": "client_credentials"},
        headers={"Authorization": _basic_auth("id-1", "wrong-secret")},
    )
    assert response.status_code in (400, 401)

    payload = client.get("/health").get_json()
    assert payload["token_issuance"]["failure"] == 1
    assert payload["token_issuance"]["recent"][0]["error"]


def test_request_id_context_does_not_leak_between_requests(client):
    client.get("/health", headers={"X-Request-ID": "leak-check"})
    assert get_request_id() is None
