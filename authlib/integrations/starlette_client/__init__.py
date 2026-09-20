from starlette.responses import JSONResponse

from authlib.common.log_context import bind_request_id_from_headers
from authlib.common.log_context import get_request_id
from authlib.common.metrics import TokenMetrics

from ..base_client import BaseOAuth
from ..base_client import OAuthError
from .apps import StarletteOAuth1App
from .apps import StarletteOAuth2App
from .integration import StarletteIntegration


class OAuth(BaseOAuth):
    oauth1_client_cls = StarletteOAuth1App
    oauth2_client_cls = StarletteOAuth2App
    framework_integration_cls = StarletteIntegration

    def __init__(self, config=None, cache=None, fetch_token=None, update_token=None):
        super().__init__(
            cache=cache, fetch_token=fetch_token, update_token=update_token
        )
        self.config = config
        self.token_metrics = TokenMetrics()

    def create_client(self, name):
        client = super().create_client(name)
        if client is not None:
            client.token_metrics = self.token_metrics
        return client

    def get_health_status(self, last_n=10):
        """Build a JSON-serializable health status payload containing the
        client key (credential) status, the registered remote apps, and
        the token exchange success/failure counters with the most recent
        ``last_n`` events. It performs no token or grant validation.
        """
        clients = {}
        for name in sorted(self._registry):
            clients[name] = _describe_client(self._clients.get(name))
        return {
            "status": "ok",
            "request_id": get_request_id(),
            "token_signer": clients,
            "grants": {"registered_clients": sorted(self._registry)},
            "token_issuance": self.token_metrics.snapshot(last_n),
        }

    def create_health_response(self, request=None, last_n=10):
        """Create a ``JSONResponse`` for a ``/health`` endpoint. The
        endpoint performs no grant or token validation."""
        if request is not None:
            bind_request_id_from_headers(request.headers)
        return JSONResponse(self.get_health_status(last_n=last_n))

    async def health_endpoint(self, request):
        """ASGI view for a ``/health`` endpoint::

        Route("/health", oauth.health_endpoint)
        """
        return self.create_health_response(request)


def _describe_client(client):
    if client is None:
        return {
            "client_id": "missing",
            "client_secret": "missing",
            "server_metadata_url": "missing",
        }
    return {
        "client_id": "configured" if getattr(client, "client_id", None) else "missing",
        "client_secret": (
            "configured" if getattr(client, "client_secret", None) else "missing"
        ),
        "server_metadata_url": (
            "configured" if getattr(client, "server_metadata_url", None) else "missing"
        ),
    }


__all__ = [
    "OAuth",
    "OAuthError",
    "StarletteIntegration",
    "StarletteOAuth1App",
    "StarletteOAuth2App",
]
