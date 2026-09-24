#!/usr/bin/env bash
# 一键启动后端（无 PostgreSQL 时自动回退 /tmp/routebench.db）
set -euo pipefail
cd "$(dirname "$0")/backend"
export ROUTEBENCH_DSN="${ROUTEBENCH_DSN:-postgresql+psycopg://routebench:routebench@localhost:5432/routebench}"
export ROUTEBENCH_SQLITE="${ROUTEBENCH_SQLITE:-/tmp/routebench.db}"
exec python3 -m uvicorn app.main:app --reload --port 8000
