# Deploying on TrueNAS SCALE

nas_scanner runs on TrueNAS SCALE 24.10 or later (the Docker-based releases) as one compose
stack of six containers, all from `deploy/portainer-compose.yml`. There are two ways to run it:

- **A Portainer Git-repository stack with GitOps updates** (recommended): Portainer redeploys
  by itself after every merge to `main`. See [deploy-portainer.md](deploy-portainer.md) for the
  stack itself; this page covers what to prepare on TrueNAS first.
- **Plain `docker compose` from a checkout** on the host, over SSH, at the end of this page.

| Service | Purpose | Memory limit |
|---|---|---|
| `db` | PostgreSQL 16, data in `<data dir>/db` | `NASSCAN_DB_MEMORY_LIMIT` (1g) |
| `migrate` | One-off: applies migrations, then exits | app limit |
| `api` | API and web UI on `NASSCAN_API_PUBLISH_PORT` (8010) | `NASSCAN_APP_MEMORY_LIMIT` (1g) |
| `scanner` | Scheduled scans, threat intel, notifications; the scan root read-only at `/scan` | app limit |
| `clamd` | ClamAV; the scanner streams files to it | `NASSCAN_CLAMD_MEMORY_LIMIT` (3g) |
| `backup` | Daily `pg_dump` into `<data dir>/backups` ([backups.md](backups.md)) | app limit |

Plan on about **4 GB of RAM** for the stack: clamd holds its signatures in about 1.5 GB and
briefly needs twice that while it reloads them after an update, which is why its limit is 3g.
ZFS gives memory back from its cache as the containers need it.

## 1. A dataset for the app

Create a dataset for the app's own data, e.g. `/mnt/<pool>/apps/nas_scanner`
(*Datasets → Add Dataset*, preset **Generic**). The stack fills it:

| Path | Owner | What |
|---|---|---|
| `db/` | uid 999 (postgres) | The database, a few hundred MB per million files |
| `backups/` | uid 10001 (nasscan), mode 700 | Database dumps |

Both are created on the first start; there's nothing to set up by hand. Include the dataset
in your snapshot and replication tasks like any other.

**Keep it out of the scan root,** or the scanner reads its own database. If it has to be
inside, add its path to `NASSCAN_EXCLUDE_GLOBS` (step 3).

## 2. Choosing the scan root

`NASSCAN_SCAN_ROOT` is the host path the scanner sees as `/scan`, mounted **read-only**: the
scanner can't change, move or delete anything there. Usually it's the pool, e.g. `/mnt/tank`,
so every dataset is covered, including ones you add later.

- **Nested datasets are included.** Docker's bind mount is recursive, so the datasets under
  the root are scanned too. One created later appears after the stack restarts (the next
  redeploy does it).
- **Snapshots aren't scanned.** `.zfs` is excluded by default, and is hidden unless a dataset
  has *Snapdir* set to visible.
- **Start small if you like.** Point the root at one dataset for the first full scan to see
  how fast it goes on your hardware, then widen it. Moving the root marks the old files
  removed and reads the new ones.

### Permissions

By default the scanner reads **every file**, whatever its permissions: a chmod 700 home
folder or a dataset with a restrictive ACL is scanned too. It keeps one Linux capability for
this, `DAC_READ_SEARCH` (read any file and list any folder, but never write), and runs as uid
10001 otherwise ([security.md](security.md)).

With `NASSCAN_SCANNER_READ_ALL=false` it gives that up and reads only what uid 10001 may: in
practice world-readable files. Each scan lists the files and folders it couldn't open on its
page. To cover them without read-all, give uid 10001 read and traverse rights in the
dataset's ACL (*Datasets → Edit Permissions*).

## 3. Exclusions

`NASSCAN_EXCLUDE_GLOBS` is a comma-separated list. A name without a slash is skipped wherever
it appears; a pattern with a slash matches a path under the scan root. The default:

```
.zfs,ix-apps,.ix-apps,.ix-virt,.Trash-*,$RECYCLE.BIN,@eaDir
```

That skips ZFS snapshots, TrueNAS's own app and VM storage, and the trash and thumbnail
folders desktop clients leave. Add:

- **The app's dataset** if it's under the scan root: `apps/nas_scanner`.
- **Other apps' databases** that change constantly and can't hold anything you'd run, if
  scanning them is just churn: e.g. `apps/immich/postgres`.
- **Backup targets** written by other machines' backup software, if they're huge and
  encrypted (encrypted data can't be scanned anyway). Keep plain file copies in.

Symlinks are never followed, so a link out of the scan root can't take the scanner elsewhere.

## 4. Network and port

The UI and API are on `NASSCAN_API_PUBLISH_PORT` (8010). Every other container is on the
stack's private network only: the database and clamd publish no ports. To use HTTPS, see
[security.md](security.md#https-through-a-reverse-proxy).

## 5. The stack

Continue with [deploy-portainer.md](deploy-portainer.md#creating-the-stack). After the first
deploy:

1. Open the UI and log in with `NASSCAN_ADMIN_PASSWORD`.
2. **Status** shows each engine: clamd takes a few minutes to download its signatures on the
   first start, and YARA downloads its rules straight away. The first backup appears there
   within a minute.
3. Under **Scan now** on the dashboard, press **Everything** for the first full scan, or wait
   for Sunday's.
4. Set up email ([notifications.md](notifications.md)) and press **Send a test**.

## Plain `docker compose` instead of Portainer

The same compose file runs from a checkout on the host. The image is pulled from GHCR as
usual; `deploy/compose.build.yml` builds it locally instead.

1. Give an SSH user docker rights: on TrueNAS, *Allowed sudo commands with no password* for
   `/usr/bin/docker`. Docker access is effectively root, so keep that user's key safe.
2. Clone and configure:

   ```sh
   cd /mnt/<pool>/apps/nas_scanner
   git clone https://github.com/drewsum/nas_scanner.git src && cd src
   cp .env.example .env && chmod 600 .env
   ```

   Add these at the top of `.env`, then fill in the rest (`POSTGRES_PASSWORD`,
   `NASSCAN_ADMIN_PASSWORD`, the scan root, any API keys):

   ```sh
   COMPOSE_PROJECT_NAME=nasscan
   COMPOSE_FILE=deploy/portainer-compose.yml
   NASSCAN_DATA_DIR=/mnt/<pool>/apps/nas_scanner
   NASSCAN_SCAN_ROOT=/mnt/<pool>
   ```

3. Start it: `sudo docker compose up -d --wait`. `--wait` returns once every service is
   healthy and `migrate` has exited.
4. **Updating:** `git pull && sudo docker compose up -d --wait`. The pull brings the new image
   tag with it.

To build on the host instead of pulling, add `:deploy/compose.build.yml` to `COMPOSE_FILE` and
set `NASSCAN_IMAGE=nasscan:local`, then `sudo docker compose up -d --build --wait`.

## Health checks

Every long-running container has one, so Portainer and `docker ps` show what's wrong:

| Service | Healthy when |
|---|---|
| `db` | `pg_isready` answers |
| `api` | `/api/health` answers and the database query in it works |
| `scanner` | its heartbeat file was touched in the last minute (the main loop is alive) |
| `clamd` | clamd answers `PING` |
| `backup` | its loop is alive (heartbeat within 15 minutes) |

`api`, `scanner` and `backup` wait for `migrate` to finish, which waits for `db` to be
healthy. Beyond the containers, the scanner watches the engines and the backups: an engine in
trouble for half an hour, a failed backup, or no backup for two days sends a notification,
and another when it's fixed ([notifications.md](notifications.md)).
