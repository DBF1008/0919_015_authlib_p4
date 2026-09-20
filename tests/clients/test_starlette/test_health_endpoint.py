import json

import pytest
from starlette.requests import Request

from authlib.integrations.starlette_client import OAuth
from authlib.integrations.starlette_client import OAuthError


def make_request(headers=None, query_string=b""):
    raw_headers = [
        (key.lower().encode("latin-1"), value.encode("latin-1"))
        for key, value in (headers or {}).items()
    ]
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": raw_headers,
            "query_string": query_string,
        }
    )


def test_health_status():
    oauth = OAuth()
    oauth.register("dev", client_id="dev", client_secret="dev-secret")
    oauth.register("public", client_id="public")

    status = oauth.get_health_status()
    assert status["status"] == "ok"
    assert status["grants"]["registered_clients"] == ["dev", "public"]
    assert status["token_signer"]["dev"]["client_id"] == "configured"
    assert status["token_signer"]["dev"]["client_secret"] == "configured"
    assert status["token_signer"]["public"]["client_secret"] == "missing"
    assert status["token_issuance"] == {
        "success": 0,
        "failure": 0,
        "total": 0,
        "recent": [],
    }


def test_health_response_binds_request_id():
    oauth = OAuth()
    resp = oauth.create_health_response(make_request({"X-Request-ID": "req-1"}))
    assert resp.status_code == 200
    body = json.loads(resp.body)
    assert body["request_id"] == "req-1"


def test_health_response_generates_request_id():
    oauth = OAuth()
    resp = oauth.create_health_response(make_request())
    body = json.loads(resp.body)
    assert body["request_id"]
    assert len(body["request_id"]) == 32


async def test_health_endpoint_asgi_view():
    oauth = OAuth()
    resp = await oauth.health_endpoint(make_request())
    assert resp.status_code == 200
    body = json.loads(resp.body)
    assert body["status"] == "ok"


async def test_authorize_access_token_records_failure():
    oauth = OAuth()
    oauth.register(
        "dev",
        client_id="dev",
        client_secret="dev-secret",
        access_token_url="https://as.test/token",
    )
    client = oauth.create_client("dev")
    request = make_request(query_string=b"error=access_denied")
    with pytest.raises(OAuthError):
        await client.authorize_access_token(request)

    snapshot = oauth.token_metrics.snapshot()
    assert snapshot["failure"] == 1
    assert snapshot["success"] == 0
    assert snapshot["recent"][0]["outcome"] == "failure"
    assert snapshot["recent"][0]["request_id"]
