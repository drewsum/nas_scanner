# Deploying on TrueNAS with Portainer (GitOps)

The server runs nas_scanner as a Portainer **Git-repository stack** from
`deploy/portainer-compose.yml`, with **GitOps updates** turned on. Unlike network_mapper, nothing
is built on the host: GitHub Actions builds the image and publishes it to GHCR.

```
push to main ──► Actions: ci checks ──► build + push ghcr.io/drewsum/nas_scanner:sha-<short>
                                          │
                                          └─► commit "deploy: sha-<short> [skip ci]"
                                              (rewrites the image: line in portainer-compose.yml)
                                              to main, and move the deploy branch to it
Portainer polls the deploy branch every 5 min ──► sees the new commit ──► pulls, redeploys
```

Portainer tracks the `deploy` branch, which only ever points at a tag-bump commit, so it never
deploys a merge before its image is built. (Tracking `main` instead would: a merge that changes
the compose file along with the code would start with the previous image for a few minutes, and
a container whose command is new fails to start.) Don't commit to `deploy` by hand; the release
workflow moves it.

The UI header shows the running commit (hover the API pill), so you can see when a redeploy has
landed.

| Service | Purpose |
|---|---|
| `db` | PostgreSQL 16, data in `${NASSCAN_DATA_DIR}/db` |
| `migrate` | one-off: applies migrations, then exits |
| `api` | API + UI on `${NASSCAN_API_PUBLISH_PORT}` |
| `scanner` | nightly incremental and weekly full scans; mounts `${NASSCAN_SCAN_ROOT}` read-only at `/scan` |
| `clamd` | ClamAV with official and unofficial signatures (`deploy/clamd`); the scanner streams files to it, so it has no access to the data |
| `backup` | daily `pg_dump` into `${NASSCAN_DATA_DIR}/backups`, keeping 14 |

Both images come from the same GHCR package: the app as `sha-<short>` and clamd as
`clamd-sha-<short>`. The release workflow bumps both tags in one commit.

## One-time setup

First prepare TrueNAS: the app's dataset, the scan root and exclusions, and memory
([deploy-truenas.md](deploy-truenas.md)).

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
4. **API keys** (optional, all free): see [below](#api-keys).

## Creating the stack

In Portainer: **Stacks → Add stack → Repository**.

- Repository URL: `https://github.com/drewsum/nas_scanner`. Reference: `refs/heads/deploy`.
  (A stack made earlier on `refs/heads/main`: change it under the stack's *Git settings*.)
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
| `NASSCAN_APP_MEMORY_LIMIT` / `NASSCAN_DB_MEMORY_LIMIT` / `NASSCAN_CLAMD_MEMORY_LIMIT` | Memory limits per container (default `1g` / `1g` / `3g`). |

Set `NASSCAN_ADMIN_PASSWORD` on the server: without it the UI and API are open to anyone on the
LAN, and the UI warns about it. Changing it logs everyone out.

For email alerts, set `NASSCAN_APPRISE_URLS` and `NASSCAN_PUBLIC_URL`
([notifications](notifications.md)), then press **Send a test** under Reports.

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

## Engines

Every file that's read goes through these engines:

| Engine | What it checks | Updates |
|---|---|---|
| ClamAV | Official signatures plus Sanesecurity's unofficial sets (malware, phishing, macro and script signatures) | freshclam and fangfrisch inside the clamd container, hourly |
| YARA | YARA Forge's core rule package (5000+ rules from many public repos, including most of signature-base); `NASSCAN_YARA_SOURCES` picks bigger packages or signature-base itself; your own rules from `/rules` | downloaded and compiled daily; rules that don't compile are skipped |
| Heuristics | `movie.mkv.exe`, programs named as media or documents, programs and scripts in media folders, right-to-left name tricks | built in |
| Documents | Office macros (auto-run, shell commands, downloads) with oletools; PDF JavaScript, auto-open actions, `/Launch`, embedded files | built in |
| 3D print files | 3MF/AMF members unpacked and scanned by the other engines; programs hidden inside; G-code that runs host commands or flashes firmware; files named `.stl` that aren't STL | built in |

**Large media.** Movies and music bigger than `NASSCAN_LARGE_FILE_MB` (512 MB), named as media
and confirmed as media by their real type, are read only at the start and end
(`NASSCAN_PARTIAL_CHUNK_MB` each). That catches a program disguised as a movie and malware
appended to one, without reading 50 GB films. A file named `.mkv` that isn't really video is
read whole. These files get no hashes, so threat intel skips them.

**Memory.** clamd needs about 1.5 GB (`NASSCAN_CLAMD_MEMORY_LIMIT`, default 3g); the scanner
holds up to `NASSCAN_SCAN_WORKERS` x `NASSCAN_MEMORY_READ_MB` of file data at once.

**Permissions.** The scanner reads every file whatever its permissions, read-only, keeping the
one capability that allows it (`NASSCAN_SCANNER_READ_ALL`, on by default;
[deploy-truenas.md](deploy-truenas.md#permissions)). Files it still can't open are listed as
errors on each scan.

## Threat intel

Only hashes leave the NAS. Nothing is ever uploaded.

**Hash feeds** are downloaded daily and matched locally against every file that has a hash,
so they cover every file at no cost. A match is a *malicious* detection.

| Feed | Key | What |
|---|---|---|
| `malwarebazaar` | `NASSCAN_ABUSECH_AUTH_KEY` | Every sample in MalwareBazaar (a full export weekly, the last 48 hours daily) |
| `threatfox` | `NASSCAN_ABUSECH_AUTH_KEY` | File hashes among ThreatFox's IOCs from the last six months |
| `virusshare` | none | The newest `NASSCAN_VIRUSSHARE_LISTS` (16) VirusShare MD5 lists; recent lists hold 65,536 hashes each, so the default is about a million hashes and 160 MB of database (backups leave them out; they are downloaded again after a restore) |

The abuse.ch key is free at [auth.abuse.ch](https://auth.abuse.ch/). abuse.ch documents the
"recent" export URLs publicly. The full-export URLs this app uses follow the same pattern
(`.../v2/files/exports/<key>/full.csv.zip`) but sit behind their login. If a feed shows an HTTP
error, compare the URL on abuse.ch's export page and add it with `NASSCAN_INTEL_EXTRA_FEEDS`.
That setting also adds any other hash list, such as URLhaus payloads:
`urlhaus=https://urlhaus-api.abuse.ch/v2/files/exports/{abusech_key}/<file from their page>`.

**Live lookups** only see files worth a lookup: executables, scripts, macro documents,
archives, PDFs, and anything a local engine flagged, most suspicious first. Photos, films and
plain documents never use quota.

1. **CIRCL hashlookup** (no key) runs first, on SHA-1. Files it knows from NSRL and other
   software sets are known good, and the other providers skip them. CIRCL also flags files it
   lists as known malicious.
2. Files a feed already lists are skipped too.
3. The rest go to each provider that has a key, within its daily budget and per-minute rate.

| Provider | Key | Free-tier defaults (requests per day / per minute) |
|---|---|---|
| CIRCL hashlookup | none | 20,000 / 30, 100 hashes per request |
| Team Cymru MHR | none | 5,000 / 10, 200 hashes per request |
| MalwareBazaar, YARAify | `NASSCAN_ABUSECH_AUTH_KEY` | 2,000 / 30 each |
| VirusTotal | `NASSCAN_VIRUSTOTAL_API_KEY` | 500 / 4 |
| Hybrid Analysis | `NASSCAN_HYBRID_ANALYSIS_API_KEY` | 5,000 / 20 |
| MetaDefender Cloud | `NASSCAN_METADEFENDER_API_KEY` | 2,000 / 20 |
| AlienVault OTX | `NASSCAN_OTX_API_KEY` | 10,000 / 30 |
| Kaspersky OpenTIP | `NASSCAN_OPENTIP_API_KEY` | 1,000 / 10 |

- **Limits.** Override a limit with `NASSCAN_INTEL_LIMITS`, e.g. `virustotal=1000/30` for a paid
  plan. Budgets reset at 00:00 UTC and survive restarts.
- **Errors.** A provider that answers "rate limited" or rejects its key is paused, for the time
  it asks or for 15 minutes to 6 hours.
- **Rechecks.** Answers are cached. "Not found" and clean answers are asked again after
  `NASSCAN_INTEL_RECHECK_DAYS` (7), hits after `NASSCAN_INTEL_HIT_RECHECK_DAYS` (30), and
  known-good answers after 90 days.
- **Dashboard.** The **Threat intel** panel shows every source: on or off (and why), feed sizes,
  quota used today, the last success, and how many hashes wait.

## API keys

Every key is optional and free. Without any, the hash feeds that need no key (VirusShare),
CIRCL and Team Cymru still run. Each key goes in the stack's environment variables; the
**Threat intel** panel under **Status** shows whether it was accepted.

| Variable | Where to get it |
|---|---|
| `NASSCAN_ABUSECH_AUTH_KEY` | [auth.abuse.ch](https://auth.abuse.ch/): sign in with an existing account (GitHub, Google and others), then generate an Auth-Key on your profile. One key covers MalwareBazaar, ThreatFox and YARAify, feeds and lookups. |
| `NASSCAN_VIRUSTOTAL_API_KEY` | [virustotal.com](https://www.virustotal.com/gui/join-us): sign up, then your name (top right) → *API key*. |
| `NASSCAN_HYBRID_ANALYSIS_API_KEY` | [hybrid-analysis.com](https://www.hybrid-analysis.com/signup): sign up, then create a key in your profile's API key section. |
| `NASSCAN_METADEFENDER_API_KEY` | [metadefender.opswat.com](https://metadefender.opswat.com/): sign up; the key is on your account page. |
| `NASSCAN_OTX_API_KEY` | [otx.alienvault.com](https://otx.alienvault.com/): sign up; the key is on your settings page (*OTX Key*). |
| `NASSCAN_OPENTIP_API_KEY` | [opentip.kaspersky.com](https://opentip.kaspersky.com/): sign in, then request a token in your account's API section. |

The keys only allow lookups, and only hashes are sent ([security.md](security.md#what-leaves-the-nas)).
Update the stack after adding one; the scanner picks it up on restart.

## Health and backups

Every long-running container has a health check, and the scanner sends a notification when
an engine or the backups stop working ([deploy-truenas.md](deploy-truenas.md#health-checks)).
The database is dumped daily; restoring is described in [backups.md](backups.md). How the
containers are locked down is in [security.md](security.md).

## Rolling back

Either revert the offending commit on `main` (a new image is built and deployed), or set
`NASSCAN_IMAGE=ghcr.io/drewsum/nas_scanner:sha-<older>` in the stack's environment variables and
update the stack. Every `sha-` tag stays in GHCR.
