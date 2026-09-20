"""authlib.common.health.
~~~~~~~~~~~~~~~~~~~~~~~~~

Health check snapshot builders. The payload reports the token signer key
state (without leaking secret material), the registered grant types and
the recent token issuance success/failure counters. Building the snapshot
never touches grant or token validation logic.
"""

from .metrics import get_metrics

#: Default component name used in health payloads.
DEFAULT_COMPONENT = "authorization_server"


def inspect_token_generators(token_generators):
    """Report key state for each registered token generator.

    Only non-sensitive metadata is exposed: algorithm, whether a signing
    key is configured, key count and key ids -- never key material.
    """
    states = []
    for name, generator in (token_generators or {}).items():
        alg = getattr(generator, "alg", None)
        jwks = None
        get_jwks = getattr(generator, "get_jwks", None)
        if callable(get_jwks):
            try:
                jwks = get_jwks()
            except Exception:
                jwks = None
        keys = jwks.get("keys") if isinstance(jwks, dict) else None
        kids = []
        if keys:
            kids = [k["kid"] for k in keys if isinstance(k, dict) and k.get("kid")]
        states.append(
            {
                "name": name,
                "alg": alg,
                "key_configured": bool(keys),
                "key_count": len(keys) if keys else 0,
                "kids": kids,
            }
        )
    return states


def build_health_snapshot(
    grant_types=None,
    token_generators=None,
    metrics=None,
    last_n=None,
    component=DEFAULT_COMPONENT,
    key_state_provider=None,
):
    """Build the JSON-serializable health check payload.

    :param grant_types: registered grant type names.
    :param token_generators: mapping of name to token generator, inspected
        for signer key state.
    :param metrics: a :class:`~authlib.common.metrics.TokenIssueMetrics`
        instance for issuance counters.
    :param last_n: limit counters to the most recent N issuance events.
    :param component: component name reported in the payload.
    :param key_state_provider: optional callable returning the ``signers``
        list directly, e.g. for HSM-backed signers.
    """
    if key_state_provider is not None:
        signers = list(key_state_provider())
    else:
        signers = inspect_token_generators(token_generators)

    if metrics is None:
        metrics = get_metrics(component)
    snapshot = metrics.snapshot(last_n=last_n)
    token_issuance = {
        "window": snapshot["window"],
        "success": snapshot["success"],
        "failure": snapshot["failure"],
        "recent": snapshot["recent"],
    }

    return {
        "status": "ok",
        "component": component,
        "grant_types": list(grant_types or []),
        "signers": signers,
        "token_issuance": token_issuance,
    }
