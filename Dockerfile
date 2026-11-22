# One image for every role (api / scanner / migrate / backup); compose picks the command.
# CI builds it and pushes it to ghcr.io/drewsum/nas_scanner (.github/workflows/release.yml).

FROM node:24-slim AS web
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM python:3.12-slim-bookworm
COPY --from=ghcr.io/astral-sh/uv:0.11.17 /uv /bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/app/.venv \
    PATH=/app/.venv/bin:$PATH \
    PYTHONUNBUFFERED=1

# libmagic: real file types (python-magic). pg_dump and pg_restore for `nasscan backup` and
# `nasscan restore`, from PostgreSQL's own apt repository: they must be at least the server's
# major version (16), and Debian's are 15. yara-python's wheel bundles libyara.
ADD https://www.postgresql.org/media/keys/ACCC4CF8.asc /usr/share/keyrings/pgdg.asc
RUN chmod 644 /usr/share/keyrings/pgdg.asc \
 && echo "deb [signed-by=/usr/share/keyrings/pgdg.asc] https://apt.postgresql.org/pub/repos/apt bookworm-pgdg main" > /etc/apt/sources.list.d/pgdg.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends libmagic1 postgresql-client-16 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app/backend
COPY backend/pyproject.toml backend/uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY backend/ ./
RUN uv sync --frozen --no-dev

COPY --from=web /web/dist /app/web-dist
ENV NASSCAN_WEB_DIST_DIR=/app/web-dist

ARG GIT_SHA=dev
ENV NASSCAN_GIT_SHA=$GIT_SHA

RUN useradd --system --uid 10001 nasscan
USER nasscan
EXPOSE 8000
CMD ["nasscan", "api"]
