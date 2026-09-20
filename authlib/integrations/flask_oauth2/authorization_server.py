from flask import Response
from flask import g
from flask import json
from flask import request as flask_req
from werkzeug.utils import import_string

from authlib.common.log_context import REQUEST_ID_HEADER
from authlib.common.log_context import ensure_request_id
from authlib.common.log_context import extract_request_id
from authlib.common.log_context import get_request_id
from authlib.common.log_context import reset_request_id
from authlib.common.security import generate_token
from authlib.oauth2 import AuthorizationServer as _AuthorizationServer
from authlib.oauth2.rfc6750 import BearerTokenGenerator

from .requests import FlaskJsonRequest
from .requests import FlaskOAuth2Request
from .signals import client_authenticated
from .signals import token_revoked


class AuthorizationServer(_AuthorizationServer):
    """Flask implementation of :class:`authlib.oauth2.rfc6749.AuthorizationServer`.
    Initialize it with ``query_client``, ``save_token`` methods and Flask
    app instance::

        def query_client(client_id):
            return Client.query.filter_by(client_id=client_id).first()


        def save_token(token, request):
            if request.user:
                user_id = request.user.id
            else:
                user_id = None
            client = request.client
            tok = Token(client_id=client.client_id, user_id=user.id, **token)
            db.session.add(tok)
            db.session.commit()


        server = AuthorizationServer(app, query_client, save_token)
        # or initialize lazily
        server = AuthorizationServer()
        server.init_app(app, query_client, save_token)
    """

    #: Component name used for metrics and health reporting.
    _metrics_component = "flask_authorization_server"

    def __init__(self, app=None, query_client=None, save_token=None):
        super().__init__()
        self._query_client = query_client
        self._save_token = save_token
        self._error_uris = None
        if app is not None:
            self.init_app(app)

    def init_app(self, app, query_client=None, save_token=None):
        """Initialize later with Flask app instance."""
        if query_client is not None:
            self._query_client = query_client
        if save_token is not None:
            self._save_token = save_token
        self.load_config(app.config)
        self._register_observability(app)

    def _register_observability(self, app):
        """Register request-id tracking and the ``/health`` endpoint."""
        state = app.extensions.setdefault("authlib_observability", {})
        if "request_id" not in state:
            app.before_request(_bind_request_id)
            app.after_request(_echo_request_id)
            app.teardown_request(_reset_request_id)
            state["request_id"] = True
        if "health" not in state:
            app.add_url_rule(
                "/health",
                endpoint="authlib_health",
                view_func=self.create_health_response,
                methods=["GET"],
            )
            state["health"] = True

    def create_health_response(self, last_n=None):
        """Flask ``GET /health`` view. It reports signer key state,
        registered grant types and recent token issuance counters, and
        never performs grant or token validation.
        """
        snapshot = self.create_health_snapshot(last_n=last_n)
        return Response(
            json.dumps(snapshot),
            status=200,
            headers={"Content-Type": "application/json"},
        )

    def load_config(self, config):
        self.register_token_generator(
            "default", self.create_bearer_token_generator(config)
        )
        self.scopes_supported = config.get("OAUTH2_SCOPES_SUPPORTED")
        self._error_uris = config.get("OAUTH2_ERROR_URIS")

    def query_client(self, client_id):
        return self._query_client(client_id)

    def save_token(self, token, request):
        return self._save_token(token, request)

    def get_error_uri(self, request, error):
        if self._error_uris:
            uris = dict(self._error_uris)
            return uris.get(error.error)

    def create_oauth2_request(self, request):
        return FlaskOAuth2Request(flask_req)

    def create_json_request(self, request):
        return FlaskJsonRequest(flask_req)

    def handle_response(self, status_code, payload, headers):
        if isinstance(payload, dict):
            payload = json.dumps(payload)
        return Response(payload, status=status_code, headers=headers)

    def send_signal(self, name, *args, **kwargs):
        if name == "after_authenticate_client":
            client_authenticated.send(self, *args, **kwargs)
        elif name == "after_revoke_token":
            token_revoked.send(self, *args, **kwargs)

    def create_bearer_token_generator(self, config):
        """Create a generator function for generating ``token`` value. This
        method will create a Bearer Token generator with
        :class:`authlib.oauth2.rfc6750.BearerToken`.

        Configurable settings:

        1. OAUTH2_ACCESS_TOKEN_GENERATOR: Boolean or import string, default is True.
        2. OAUTH2_REFRESH_TOKEN_GENERATOR: Boolean or import string, default is False.
        3. OAUTH2_TOKEN_EXPIRES_IN: Dict or import string, default is None.

        By default, it will not generate ``refresh_token``, which can be turn on by
        configure ``OAUTH2_REFRESH_TOKEN_GENERATOR``.

        Here are some examples of the token generator::

            OAUTH2_ACCESS_TOKEN_GENERATOR = "your_project.generators.gen_token"

            # and in module `your_project.generators`, you can define:


            def gen_token(client, grant_type, user, scope):
                # generate token according to these parameters
                token = create_random_token()
                return f"{client.id}-{user.id}-{token}"

        Here is an example of ``OAUTH2_TOKEN_EXPIRES_IN``::

            OAUTH2_TOKEN_EXPIRES_IN = {
                "authorization_code": 864000,
                "urn:ietf:params:oauth:grant-type:jwt-bearer": 3600,
            }
        """
        conf = config.get("OAUTH2_ACCESS_TOKEN_GENERATOR", True)
        access_token_generator = create_token_generator(conf, 42)

        conf = config.get("OAUTH2_REFRESH_TOKEN_GENERATOR", False)
        refresh_token_generator = create_token_generator(conf, 48)

        expires_conf = config.get("OAUTH2_TOKEN_EXPIRES_IN")
        expires_generator = create_token_expires_in_generator(expires_conf)
        return BearerTokenGenerator(
            access_token_generator, refresh_token_generator, expires_generator
        )


def create_token_expires_in_generator(expires_in_conf=None):
    if isinstance(expires_in_conf, str):
        return import_string(expires_in_conf)

    data = {}
    data.update(BearerTokenGenerator.GRANT_TYPES_EXPIRES_IN)
    if isinstance(expires_in_conf, dict):
        data.update(expires_in_conf)

    def expires_in(client, grant_type):
        return data.get(grant_type, BearerTokenGenerator.DEFAULT_EXPIRES_IN)

    return expires_in


def create_token_generator(token_generator_conf, length=42):
    if callable(token_generator_conf):
        return token_generator_conf

    if isinstance(token_generator_conf, str):
        return import_string(token_generator_conf)
    elif token_generator_conf is True:

        def token_generator(*args, **kwargs):
            return generate_token(length)

        return token_generator


def _bind_request_id():
    """Flask ``before_request`` handler binding the request id."""
    _, token = ensure_request_id(extract_request_id(flask_req.headers))
    g._authlib_request_id_token = token


def _echo_request_id(response):
    """Flask ``after_request`` handler echoing the request id header."""
    request_id = get_request_id()
    if request_id:
        response.headers[REQUEST_ID_HEADER] = request_id
    return response


def _reset_request_id(exc=None):
    """Flask ``teardown_request`` handler cleaning up the log context."""
    token = g.pop("_authlib_request_id_token", None)
    if token is not None:
        reset_request_id(token)
