#!/usr/bin/env bash
# Full local test run: lint, backend unit + DB integration tests, web lint and build.
# DB tests use a separate `nasscan_test` database in the compose `db` container, so your
# dev data is never touched. Requires `docker compose up -d db` (started automatically).
set -euo pipefail
cd "$(dirname "$0")/.."

set -a; source ./.env; set +a

docker compose up -d --wait db >/dev/null
docker compose exec -T db psql -qtA -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
  -c "SELECT 1 FROM pg_database WHERE datname = 'nasscan_test'" | grep -q 1 \
  || docker compose exec -T db psql -q -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "CREATE DATABASE nasscan_test"

export NASSCAN_TEST_DATABASE_URL="postgresql+psycopg://${POSTGRES_USER}:${POSTGRES_PASSWORD}@127.0.0.1:${NASSCAN_DB_PUBLISH_PORT:-5434}/nasscan_test"

(cd backend && uv run ruff check . && uv run ruff format --check . && uv run pytest -q "$@")
(cd web && npm run -s lint && npm run -s build >/dev/null)
echo "all checks passed"
