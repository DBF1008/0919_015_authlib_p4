"""Framework-free tests of request_id propagation through the core server."""

from authlib.common.log_context import get_request_id
from authlib.common.metrics import reset_metrics
from authlib.oauth2.rfc6749.authorization_server import AuthorizationServer
from authlib.oauth2.rfc6749.hooks import Hookable


class _FakeRawRequest:
    def __init__(self, headers=None, form=None):
        self.headers = headers
        self._form = form or {}
        self.method = "POST"
        self.url = "https://as.test/token"

    @property
    def values(self):
        return self._form

    def get_json(self):
        return self._form

    def getlist(self, key):
        value = self._form.get(key)
        return value if isinstance(value, list) else [value]


class _FakePayload:
    def __init__(self, request, form):
        self._request = request
        self._form = form

    @property
    def data(self):
        return self._form

    @property
    def datalist(self):
        return {key: [value] for key, value in self._form.items()}

    @property
    def grant_type(self):
        return self._form.get("grant_type")

    @property
    def client_id(self):
        return self._form.get("client_id")

    @property
    def response_type(self):
        return self._form.get("response_type")

    @property
    def redirect_uri(self):
        return self._form.get("redirect_uri")

    @property
    def scope(self):
        return self._form.get("scope")

    @property
    def state(self):
        return self._form.get("state")


class _FakeOAuth2Request:
    def __init__(self, request):
        self.method = request.method
        self.url = request.url
        self.uri = request.url
        self.headers = request.headers
        self.payload = _FakePayload(self, request._form)
        self.client = None

    @property
    def args(self):
        return {}

    @property
    def form(self):
        return self.payload.data


class _RecordingServer(AuthorizationServer):
    def __init__(self):
        super().__init__()
        self.seen_ids = []

    def query_client(self, client_id):
        raise NotImplementedError

    def save_token(self, token, request):
        raise NotImplementedError

    def send_signal(self, name, *args, **kwargs):
        pass

    def create_oauth2_request(self, request):
        return _FakeOAuth2Request(request)

    def handle_response(self, status, body, headers):
        return status, body, headers


def test_request_id_from_header_flows_through_token_endpoint():
    reset_metrics()
    server = _RecordingServer()

    raw = _FakeRawRequest(
        headers={"X-Request-ID": "trace-xyz"},
        form={"grant_type": "does-not-exist"},
    )
    status, body, headers = server.create_token_response(raw)
    assert status == 400
    assert body["error"] == "unsupported_grant_type"
    assert get_request_id() is None

    snapshot = server.metrics.snapshot()
    assert snapshot["failure"] == 1
    assert snapshot["recent"][0]["request_id"] == "trace-xyz"


def test_missing_request_id_is_generated():
    reset_metrics()
    server = _RecordingServer()
    raw = _FakeRawRequest(form={"grant_type": "nope"})
    server.create_token_response(raw)

    rid = server.metrics.snapshot()["recent"][0]["request_id"]
    assert rid and len(rid) >= 16


def test_hooked_method_propagates_context_to_hooks():
    from authlib.common.log_context import request_id_context
    from authlib.oauth2.rfc6749.hooks import hooked

    seen = []

    class Subject(Hookable):
        @hooked
        def run(self):
            seen.append(("body", get_request_id()))

    subject = Subject()

    def before_hook(subject):
        seen.append(("before-hook", get_request_id()))

    def after_hook(subject, result=None):
        seen.append(("after", get_request_id()))

    subject.register_hook("before_run", before_hook)
    subject.register_hook("after_run", after_hook)

    with request_id_context("hook-rid"):
        subject.run()

    assert ("before-hook", "hook-rid") in seen
    assert ("body", "hook-rid") in seen
    assert ("after", "hook-rid") in seen
    assert get_request_id() is None


def test_execute_hook_uses_instance_request_id_attribute():
    """Grants carry no ambient context; setting request_id on the Hookable
    instance must frame hook execution (used by framework integrations)."""

    seen = {}

    class Subject(Hookable):
        pass

    subject = Subject()

    def my_hook(subject):
        seen["rid"] = get_request_id()

    subject.request_id = "instance-rid"
    subject.register_hook("ping", my_hook)
    subject.execute_hook("ping")

    assert seen["rid"] == "instance-rid"
