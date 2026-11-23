# nas_scanner

Scans every file on a TrueNAS SCALE system for malicious content, nightly. It checks files with
local engines (ClamAV, YARA, file-type heuristics), matches every hash against downloaded
malware hash feeds (MalwareBazaar, ThreatFox, VirusShare), and looks up the hashes of risky files
with free threat-intel services (CIRCL, Team Cymru, VirusTotal, MalwareBazaar, YARAify, Hybrid
Analysis, MetaDefender, OTX, Kaspersky OpenTIP). Only hashes ever leave the NAS, never file contents. The NAS data is
mounted read-only: the scanner reports and never changes, moves or deletes a file. All the
evidence about a file adds up to one verdict ([how](docs/verdicts.md)); findings show in a web UI,
in reports, and by email, and can be acknowledged, ignored or allowlisted.

The web UI has a dashboard (open threats, files on the NAS, the last scan, signature age),
findings with each engine's evidence and links to VirusTotal and other providers, scan history
with live progress and what each scan couldn't read, a file search by path or hash, engine and
provider status, and Scan now (new and changed files, everything, or one folder). Alerts go
out by email or any Apprise service, with a printable report per scan, a weekly report, and
CSV/JSON exports ([how](docs/notifications.md)).

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
