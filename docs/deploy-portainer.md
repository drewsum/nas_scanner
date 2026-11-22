# Deploying on TrueNAS with Portainer (GitOps)

The server runs nas_scanner as a Portainer **Git-repository stack** from
`deploy/portainer-compose.yml`, with **GitOps updates** turned on. Unlike network_mapper, nothing
is built on the host: GitHub Actions builds the image and publishes it to GHCR.

```
push to main ──► Actions: ci checks ──► build + push ghcr.io/drewsum/nas_scanner:sha-<short>
                                          │
                                          └─► commit "deploy: sha-<short> [skip ci]"
                                              (rewrites the image: line in portainer-compose.yml)
Portainer polls the repo every 5 min ──► sees the new commit ──► pulls the image, redeploys
```

Portainer only reacts to that tag-bump commit, so it never tries to deploy an image that is
still building. The UI header shows the running commit (hover the API pill), so you can see when
a redeploy has landed.

| Service | Purpose |
|---|---|
| `db` | PostgreSQL 16, data in `${NASSCAN_DATA_DIR}/db` |
| `migrate` | one-off: applies migrations, then exits |
| `api` | API + UI on `${NASSCAN_API_PUBLISH_PORT}` |
| `scanner` | nightly incremental and weekly full scans; mounts `${NASSCAN_SCAN_ROOT}` read-only at `/scan` |
| `backup` | daily `pg_dump` into `${NASSCAN_DATA_DIR}/backups`, keeping 14 |

ClamAV (`clamd`) joins the stack in M2.

## One-time setup

1. **GHCR package visibility.** After the first run of the release workflow, open the package
   (github.com/drewsum?tab=packages → `nas_scanner` → Package settings) and set its visibility to
   **Public**, so Portainer can pull without registry credentials. (New GHCR packages start
   private even when the repo is public.) Alternatively keep it private and add a GHCR registry
   in Portainer with a token that has `read:packages`.
2. **Dataset.** Create a dataset for the app (Generic preset), e.g.
   `/mnt/<pool>/apps/nas_scanner`. The DB container creates and owns `db/` inside it on first
   start. Keep it outside the scan root, or the scanner will scan its own database.
3. **Scan root.** Decide which host path the scanner sees, e.g. `/mnt/tank`. It is mounted
   read-only; the scanner never changes a file.

## Creating the stack

In Portainer: **Stacks → Add stack → Repository**.

- Repository URL: `https://github.com/drewsum/nas_scanner`. Reference: `refs/heads/main`.
- Authentication: off (public repo).
- Compose path: `deploy/portainer-compose.yml`.
- **GitOps updates: on.** Mechanism: *Polling*, interval `5m`. Turn on **Re-pull image**
  (so a re-pushed tag is fetched too) and **Force redeployment** off.
- Environment variables: every variable from `.env.example`, filled in, including
  `NASSCAN_DATA_DIR` and `NASSCAN_SCAN_ROOT`. The dev-only `NASSCAN_WEB_PUBLISH_PORT` and
  `NASSCAN_DB_PUBLISH_PORT` aren't used.

The compose file passes each setting to the containers explicitly as `${VAR:-}`, because
Portainer doesn't write a `stack.env` that compose can read for Git stacks. When you add a new
`NASSCAN_*` setting, add it to `x-nasscan-env` in `deploy/portainer-compose.yml` too.

Deploy, then check that `db` and `api` are healthy, `migrate` exited with code 0, and `scanner`
and `backup` are healthy. The UI is at `http://<truenas-host>:<NASSCAN_API_PUBLISH_PORT>`.

## Environment variables

Same as `.env.example`, plus:

| Variable | Purpose |
|---|---|
| `NASSCAN_DATA_DIR` | Host path of the app dataset (DB in `<this>/db`, backups in `<this>/backups`). Required. |
| `NASSCAN_SCAN_ROOT` | Host path to scan, mounted read-only at `/scan`. Required. |
| `NASSCAN_API_PUBLISH_PORT` | Host port for the API and UI (default 8010; network_mapper uses 8000). Pick one no other app uses. |
| `NASSCAN_IMAGE` | Override the image (e.g. pin an older `sha-` tag to roll back). Normally unset. |
| `NASSCAN_APP_MEMORY_LIMIT` / `NASSCAN_DB_MEMORY_LIMIT` | Memory limits per container (default `1g` / `1g`). |

Set `NASSCAN_ADMIN_PASSWORD` on the server: without it the UI and API are open to anyone on the
LAN, and the UI warns about it. Changing it logs everyone out.

## Scans

- **Schedule.** `NASSCAN_INCREMENTAL_CRON` (default 02:00 nightly) reads new and changed files;
  `NASSCAN_FULL_CRON` (default 03:00 Sunday) reads every file. A file counts as changed when its
  size, modification time or inode differ from the last scan. Only one scan runs at a time: a
  scan that comes due while another is running is skipped. A full scan that's queued replaces a
  queued incremental one.
- **What's skipped.** `NASSCAN_EXCLUDE_GLOBS`: a name without a slash (`.zfs`, `ix-apps`) is
  skipped wherever it appears, and a pattern with a slash (`apps/nas_scanner`) matches a path
  under the scan root. If the app's own dataset is under the scan root, add it. Symlinks are
  never followed.
- **Load on the NAS.** `NASSCAN_MAX_READ_MBPS` (default 100) caps how fast the scanner reads, and
  `NASSCAN_SCAN_WORKERS` (default 2) how many files it reads at once. The scanner also runs at
  low CPU and IO priority. The read cap is what matters most on ZFS.
- **Restarts.** A scan interrupted by a redeploy or a reboot resumes where it stopped.
- **Removed files.** Files no longer found are marked removed. Nothing is marked removed when
  the scan root is empty (an unmounted dataset), and files under folders that couldn't be read
  are left alone.
- **Scan now.** Use the buttons on the dashboard, or
  `docker exec <scanner container> nasscan scan [--full | --path some/folder]`.

## Rolling back

Either revert the offending commit on `main` (a new image is built and deployed), or set
`NASSCAN_IMAGE=ghcr.io/drewsum/nas_scanner:sha-<older>` in the stack's environment variables and
update the stack. Every `sha-` tag stays in GHCR.
