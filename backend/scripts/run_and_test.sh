#!/usr/bin/env bash
# Run backend and test. Requires: PostgreSQL running (contexta DB), and optionally frontend.
set -e
cd "$(dirname "$0")/.."

echo "=== 1. Running backend test suite ==="
. .venv/bin/activate 2>/dev/null || python3 -m venv .venv && . .venv/bin/activate
pip install -q -r requirements.txt
python -m pytest tests/ -v --tb=short

echo ""
echo "=== 2. Starting backend (requires Postgres; Ctrl+C to stop) ==="
echo "Ensure DATABASE_URL is set (e.g. in .env) and Postgres is running."
echo "Example: docker run -d -p 5432:5432 -e POSTGRES_USER=contexta -e POSTGRES_PASSWORD=contexta -e POSTGRES_DB=contexta postgres:15-alpine"
echo ""
uvicorn app.main:app --host 0.0.0.0 --port 8000
