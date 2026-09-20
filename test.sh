#!/usr/bin/env bash
# 手动运行全部单元测试脚本。
# 用法: ./test.sh            运行所有单元测试
#       ./test.sh -k health  透传额外 pytest 参数
set -uo pipefail
cd "$(dirname "$0")"

PY=python3
if [ -x .venv/bin/python ]; then
    PY=.venv/bin/python
fi

EXTRA_ARGS=("$@")
FAILED_SUITES=()

run_suite() {
    local name="$1"
    shift
    echo
    echo "================================================================"
    echo "==> ${name}"
    echo "================================================================"
    if ! "$PY" -m pytest "$@" "${EXTRA_ARGS[@]}"; then
        FAILED_SUITES+=("${name}")
    fi
}

# 新增功能: 结构化日志 / request_id 追踪 / 健康检查
run_suite "核心: 日志上下文与指标 (tests/core/test_log_context.py)" \
    tests/core/test_log_context.py -v

run_suite "Flask: 健康检查与请求追踪 (tests/flask/test_oauth2/test_health_endpoint.py)" \
    tests/flask/test_oauth2/test_health_endpoint.py -v

run_suite "Django: 健康检查与请求追踪 (tests/django/test_oauth2/test_health_endpoint.py)" \
    tests/django/test_oauth2/test_health_endpoint.py -v

run_suite "Starlette 客户端: 健康检查 (tests/clients/test_starlette/test_health_endpoint.py)" \
    tests/clients/test_starlette/test_health_endpoint.py -v

# 既有单元测试回归
run_suite "核心回归 (tests/core)" tests/core
run_suite "Flask 集成回归 (tests/flask)" tests/flask
run_suite "Django 集成回归 (tests/django)" tests/django
run_suite "客户端回归 (tests/clients)" tests/clients

echo
if [ "${#FAILED_SUITES[@]}" -gt 0 ]; then
    echo "FAILED suites:"
    for suite in "${FAILED_SUITES[@]}"; do
        echo "  - ${suite}"
    done
    exit 1
fi
echo "All suites passed."
