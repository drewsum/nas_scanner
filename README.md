# nas_scanner

Scans every file on a TrueNAS SCALE system for malicious content, nightly. It checks files with
local engines (ClamAV, YARA, file-type heuristics) and looks up their hashes with free
threat-intel services. Only hashes ever leave the NAS, never file contents. The NAS data is
mounted read-only: the scanner reports and never changes, moves or deletes a file. Findings show
in a web UI, in reports, and by email.

Built the same way as [network_mapper](https://github.com/drewsum/network_mapper): Python 3.12
(FastAPI, SQLAlchemy, Alembic) with uv, PostgreSQL, and a React + Vite UI, all in one image
whose role (`api`, `scanner`, `migrate`, `backup`) compose picks.

Work is tracked as [milestones and issues](https://github.com/drewsum/nas_scanner/milestones).

## Development

```bash
cp .env.example .env          # fill in; NASSCAN_SCAN_ROOT=./samples for dev
docker compose up --build     # db, migrate, api :8010, scanner, clamd, Vite :5173
bash scripts/test.sh          # ruff, pytest (incl. DB tests), web lint + build
uvx pre-commit install        # the same checks before each commit
```

The Vite dev server on :5173 proxies `/api` to the api container. The api container also serves
the built UI on :8010.

## Deployment (GitOps)

Every push to `main` runs the checks, builds `ghcr.io/drewsum/nas_scanner:sha-<short>` (and
`:latest`), and commits that tag into `deploy/portainer-compose.yml`. Portainer, polling the repo,
redeploys within about five minutes. Setup: [docs/deploy-portainer.md](docs/deploy-portainer.md).
