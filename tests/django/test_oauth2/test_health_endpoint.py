import json

import pytest

from authlib.common.log_context import get_request_id
from authlib.oauth2.rfc6749 import grants

from .models import Client
from .oauth2_server import create_basic_auth


@pytest.fixture(autouse=True)
def server(server):
    server.register_grant(grants.ClientCredentialsGrant)
    return server


@pytest.fixture(autouse=True)
def client(user):
    client = Client(
        user_id=user.pk,
        client_id="client-id",
        client_secret="client-secret",
        scope="",
        grant_type="client_credentials",
        token_endpoint_auth_method="client_secret_basic",
        default_redirect_uri="https://client.test",
    )
    client.save()
    yield client
    client.delete()


def test_health_endpoint(factory, server):
    request = factory.get("/health")
    resp = server.create_health_response(request)
    assert resp.status_code == 200
    assert resp["Content-Type"] == "application/json"
    data = json.loads(resp.content)
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


def test_health_endpoint_requires_no_grant_or_token(factory, server):
    # no client credentials, no token, no grant parameters
    request = factory.get("/health")
    resp = server.create_health_response(request)
    assert resp.status_code == 200


def test_health_endpoint_counts_token_issuance(factory, server):
    request = factory.post(
        "/oauth/token",
        data={"grant_type": "client_credentials"},
        HTTP_AUTHORIZATION=create_basic_auth("client-id", "client-secret"),
    )
    resp = server.create_token_response(request)
    assert resp.status_code == 200

    request = factory.post(
        "/oauth/token",
        data={"grant_type": "client_credentials"},
        HTTP_AUTHORIZATION=create_basic_auth("client-id", "invalid-secret"),
    )
    resp = server.create_token_response(request)
    assert resp.status_code == 401

    request = factory.get("/health")
    resp = server.create_health_response(request)
    data = json.loads(resp.content)
    assert data["token_issuance"]["success"] == 1
    assert data["token_issuance"]["failure"] == 1
    assert data["token_issuance"]["total"] == 2
    recent = data["token_issuance"]["recent"]
    assert len(recent) == 2
    assert recent[0]["outcome"] == "success"
    assert recent[0]["grant_type"] == "client_credentials"
    assert recent[1]["outcome"] == "failure"
    assert recent[1]["error"] == "invalid_client"


def test_request_id_from_header(factory, server):
    captured = {}
    original_save_token = server.save_token

    def save_token(token, request):
        captured["request_id"] = get_request_id()
        return original_save_token(token, request)

    server.save_token = save_token

    request = factory.post(
        "/oauth/token",
        data={"grant_type": "client_credentials"},
        HTTP_AUTHORIZATION=create_basic_auth("client-id", "client-secret"),
        HTTP_X_REQUEST_ID="req-django-1",
    )
    resp = server.create_token_response(request)
    assert resp.status_code == 200
    assert captured["request_id"] == "req-django-1"


def test_request_id_generated_when_missing(factory, server):
    captured = {}
    original_save_token = server.save_token

    def save_token(token, request):
        captured["request_id"] = get_request_id()
        return original_save_token(token, request)

    server.save_token = save_token

    request = factory.post(
        "/oauth/token",
        data={"grant_type": "client_credentials"},
        HTTP_AUTHORIZATION=create_basic_auth("client-id", "client-secret"),
    )
    resp = server.create_token_response(request)
    assert resp.status_code == 200
    assert captured["request_id"]
    assert len(captured["request_id"]) == 32
