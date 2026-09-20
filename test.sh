#!/usr/bin/env bash
# Manual test runner for the DevOps observability feature:
# structured logging, request-id tracing and health endpoints.
#
# Environment notes:
#   - Flask 2.0 / Werkzeug 2.0 only work on Python 3.10, so the Flask
#     integration tests run under python3.10 with its site-packages.
#   - Framework-free tests also run under python3.14.
#   - Some legacy suites require the missing "joserfc" package and are
#     skipped automatically.
set -euo pipefail

cd "$(dirname "$0")"

PY314="${PY314:-python3.14}"
PY310="${PY310:-python3.10}"
PY310_PACKAGES="${PY310_PACKAGES:-/opt/homebrew/lib/python3.10/site-packages}"

echo "==> [1/3] observability unit tests (framework-free, ${PY314})"
"$PY314" -m pytest tests/devops_observability -v \
    --ignore=tests/devops_observability/test_flask_integration.py

echo "==> [2/3] observability unit tests incl. Flask integration (${PY310})"
PYTHONPATH="${PY310_PACKAGES}${PYTHONPATH:+:${PYTHONPATH}}" \
    "$PY310" -m pytest tests/devops_observability -v

echo "==> [3/3] core oauth2 regression tests (${PY314})"
if "$PY314" -c "import joserfc" 2>/dev/null; then
    "$PY314" -m pytest tests/core
else
    echo "    (joserfc not installed; running the subset that does not need it)"
    "$PY314" -m pytest tests/core/test_oauth2 \
        --ignore=tests/core/test_oauth2/test_rfc7523_client_secret.py \
        --ignore=tests/core/test_oauth2/test_rfc7523_private_key.py \
        --ignore=tests/core/test_oauth2/test_rfc7523_validator.py \
        --ignore=tests/core/test_oauth2/test_rfc7591.py \
        --ignore=tests/core/test_oauth2/test_rfc8414.py \
        --ignore=tests/core/test_oauth2/test_rfc9068_token_validator.py
fi

echo "All test suites passed."
