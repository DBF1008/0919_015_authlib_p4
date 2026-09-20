import pytest
from flask import json

from authlib.common.log_context import get_request_id
from authlib.oauth2.rfc6749.grants import ClientCredentialsGrant

from .oauth2_server import create_basic_header


@pytest.fixture(autouse=True)
def server(server, app):
    server.register_grant(ClientCredentialsGrant)
    server.register_health_endpoint(app)
    return server


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "scope": "profile",
            "redirect_uris": ["https://client.test/authorized"],
            "grant_types": ["client_credentials"],
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


def test_health_endpoint(test_client):
    rv = test_client.get("/health")
    assert rv.status_code == 200
    data = json.loads(rv.data)
    assert data["status"] == "ok"
    assert data["request_id"]
    assert data["token_signer"]["default"]["configured"] is True
    assert data["token_signer"]["default"]["type"] == "BearerTokenGenerator"
    assert data["grants"]["token"] == [
        {"name": "ClientCredentialsGrant", "grant_type": "client_credentials"}
    ]
    assert data["token_issuance"] == {
        "success": 0,
        "failure": 0,
        "total": 0,
        "recent": [],
    }


def test_health_endpoint_requires_no_grant_or_token(test_client):
    # no client credentials, no token, no grant parameters
    rv = test_client.get("/health")
    assert rv.status_code == 200


def test_health_endpoint_counts_token_issuance(test_client):
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/token",
        data={"grant_type": "client_credentials", "scope": "profile"},
        headers=headers,
    )
    assert rv.status_code == 200

    headers = create_basic_header("client-id", "invalid-secret")
    rv = test_client.post(
        "/oauth/token",
        data={"grant_type": "client_credentials"},
        headers=headers,
    )
    assert rv.status_code == 401

    rv = test_client.get("/health")
    data = json.loads(rv.data)
    assert data["token_issuance"]["success"] == 1
    assert data["token_issuance"]["failure"] == 1
    assert data["token_issuance"]["total"] == 2
    recent = data["token_issuance"]["recent"]
    assert len(recent) == 2
    assert recent[0]["outcome"] == "success"
    assert recent[0]["grant_type"] == "client_credentials"
    assert recent[1]["outcome"] == "failure"
    assert recent[1]["error"] == "invalid_client"


def test_request_id_from_header(server, test_client):
    captured = {}
    original_save_token = server._save_token

    def save_token(token, request):
        captured["request_id"] = get_request_id()
        return original_save_token(token, request)

    server._save_token = save_token

    headers = create_basic_header("client-id", "client-secret")
    headers["X-Request-ID"] = "req-flask-1"
    rv = test_client.post(
        "/oauth/token",
        data={"grant_type": "client_credentials", "scope": "profile"},
        headers=headers,
    )
    assert rv.status_code == 200
    assert captured["request_id"] == "req-flask-1"


def test_request_id_generated_when_missing(server, test_client):
    captured = {}
    original_save_token = server._save_token

    def save_token(token, request):
        captured["request_id"] = get_request_id()
        return original_save_token(token, request)

    server._save_token = save_token

    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/token",
        data={"grant_type": "client_credentials", "scope": "profile"},
        headers=headers,
    )
    assert rv.status_code == 200
    assert captured["request_id"]
    assert len(captured["request_id"]) == 32
