"""Health check endpoint for the Starlette client integration.

Mount it as a ``/health`` route::

    from starlette.routing import Route

    from authlib.integrations.starlette_client import health_endpoint

    routes = [Route("/health", health_endpoint, methods=["GET"])]

The endpoint reports the token signer key state, registered grant types
and recent token issuance counters. It never performs grant or token
validation, so it is safe to expose to load balancers.
"""

from authlib.common.health import build_health_snapshot
from authlib.common.log_context import REQUEST_ID_HEADER
from authlib.common.log_context import ensure_request_id
from authlib.common.log_context import extract_request_id
from authlib.common.log_context import reset_request_id
from authlib.common.metrics import get_metrics

#: Component name used for metrics and health reporting.
HEALTH_COMPONENT = "starlette_client"


async def health_endpoint(request):
    """Starlette ``GET /health`` endpoint (ASGI-friendly)."""
    from starlette.responses import JSONResponse

    request_id, token = ensure_request_id(extract_request_id(request.headers))
    try:
        snapshot = build_health_snapshot(
            component=HEALTH_COMPONENT,
            metrics=get_metrics(HEALTH_COMPONENT),
        )
        return JSONResponse(snapshot, headers={REQUEST_ID_HEADER: request_id})
    finally:
        reset_request_id(token)
