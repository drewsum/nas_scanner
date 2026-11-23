# Security

nas_scanner reads every file on the NAS, so it's built to be unable to change any of them,
to send nothing but hashes off the box, and to run with as few privileges as it can.

## What leaves the NAS

**Only hashes.** No file contents, ever: the scanner has no code that uploads a file.

| Where | What's sent | When |
|---|---|---|
| CIRCL hashlookup | SHA-1 of files worth a lookup | always (no key) |
| Team Cymru MHR | SHA-256 of the same, over its whois service | always (no key) |
| MalwareBazaar, YARAify, VirusTotal, Hybrid Analysis, MetaDefender, OTX, OpenTIP | SHA-256 | only with that provider's key |
| abuse.ch, VirusShare | nothing about your files: the feeds are downloaded | daily |
| ClamAV, YARA rule sources | nothing: signatures and rules are downloaded | hourly / daily |
| Your Apprise services (email) | paths, verdicts, scores, engine names, SHA-256 of flagged files | on findings, failures, reports |

- **Which files get looked up.** Executables, scripts, macro documents, archives, PDFs and
  anything a local engine flagged. Photos, films and ordinary documents never are. Files that
  CIRCL knows as published software are skipped by the rest.
- **What a hash reveals.** A provider learns that someone has a file with that hash. For a
  public file, that says little. For a private document, the hash alone reveals nothing about
  the contents, but documents are rarely looked up anyway.
- **Turning it off.** `NASSCAN_INTEL_LOOKUPS=false` stops every live lookup; the downloaded
  feeds still match locally. `NASSCAN_INTEL_DISABLED=circl,cymru` turns off individual
  providers.

Notifications go to whatever `NASSCAN_APPRISE_URLS` names, with file paths in them; email
providers store what they deliver.

## The data is read-only

- **The scan root is mounted `:ro`** into the scanner. The kernel refuses writes to it whatever
  the process does, so a bug or a malicious file that exploits a parser can't change, encrypt
  or delete NAS data through the scanner.
- **Nothing acts on findings.** There's no quarantine and no delete button. A finding is a
  report; what to do about it is yours.
- **clamd never sees the data.** The scanner streams each file's bytes to it over the stack's
  private network; its container has no mount of the NAS.
- Files are read without following symlinks, so a link can't lead outside the scan root.

## Containers

| Container | Runs as | Capabilities | Filesystem |
|---|---|---|---|
| `api` | nasscan (uid 10001) | none | read-only, `/tmp` in memory |
| `migrate` | nasscan | none | read-only, `/tmp` in memory |
| `scanner` | root at start, then nasscan | `DAC_READ_SEARCH` only, after start | read-only, `/tmp` in memory, scan root `:ro`, rules volume |
| `backup` | root at start, then nasscan | none after start | read-only, `/tmp` in memory, `backups/` |
| `clamd` | root at start, then clamav | `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `SETUID`, `SETGID` | its signature volume |
| `db` | root at start, then postgres | `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `SETUID`, `SETGID` | the data directory |

Every container has `no-new-privileges` (no setuid binary can raise privileges), a process
limit, a memory limit, and log rotation (10 MB x 3).

- **The scanner** starts as root with `DAC_READ_SEARCH`, `SETUID`, `SETGID` and `SETPCAP`, and
  immediately switches to the nasscan user with `setpriv`, keeping `DAC_READ_SEARCH` alone
  (`deploy/scanner/start.sh`). That capability lets it read every file and list every folder
  whatever their permissions, so private folders are scanned too; it grants no write access
  anywhere. Its capability bounding set is that one capability, so nothing it runs can gain
  another. `NASSCAN_SCANNER_READ_ALL=false` keeps none, and the scanner reads only what uid
  10001 may.
- **The backup service** starts as root only to hand `backups/` to the nasscan user, then
  switches to it. Dumps are readable by uid 10001 only.
- **clamd and the database** use their official images' start-up, which needs root to set up
  folders before dropping to their own users. Every capability beyond what that takes is
  dropped.
- **Ports.** Only the api's port is published. The database and clamd are reachable from
  inside the stack only.

## Secrets

All secrets come from environment variables: the Portainer stack's, or a `chmod 600` `.env`
in a checkout. None are in the image or the repo, and the app doesn't log them (HTTP request
logging is off for providers that put keys in URLs).

| Secret | What it's for |
|---|---|
| `POSTGRES_PASSWORD` | The database. Only containers in the stack can reach it. |
| `NASSCAN_ADMIN_PASSWORD` | The web UI and API. Set it: without it anyone on the LAN can use both, and the UI says so. |
| `NASSCAN_ABUSECH_AUTH_KEY`, `NASSCAN_VIRUSTOTAL_API_KEY`, `NASSCAN_HYBRID_ANALYSIS_API_KEY`, `NASSCAN_METADEFENDER_API_KEY`, `NASSCAN_OTX_API_KEY`, `NASSCAN_OPENTIP_API_KEY` | Threat intel. Free accounts; each key can only look things up. |
| `NASSCAN_APPRISE_URLS` | Notification services; the URLs embed passwords or tokens (for Gmail, an app password, not your account password). |

`pg_dump` and `pg_restore` get the database password through `PGPASSWORD` in their
environment, never on the command line.

## Logging in

- **One admin password.** A login gets a session cookie that is `HttpOnly`,
  `SameSite=Strict`, and `Secure` when the request came over HTTPS. It's signed with a key
  that combines a random secret in the database with the password, so changing the password
  logs everyone out. Sessions last `NASSCAN_SESSION_DAYS` (30).
- **Lockout.** Five failed logins from one address within five minutes lock that address out
  for a few minutes.
- **No cross-site requests.** The API only takes JSON bodies, which browsers won't send to
  another site without CORS (and nas_scanner allows none), so other sites can't act with your
  session.
- **Headers.** Every response says the page may not be framed, must not be MIME-sniffed, and
  sends no referrer to other sites.
- **What's public.** Only `/api/health` (status and the running commit) and the login flow
  answer without a session.

## HTTPS through a reverse proxy

nas_scanner serves plain HTTP. For HTTPS, put a reverse proxy in front of it and tell
nas_scanner to trust that proxy's `X-Forwarded-For` and `X-Forwarded-Proto` headers:

```sh
NASSCAN_TRUSTED_PROXIES=<the proxy's address, as the api container sees it>
NASSCAN_PUBLIC_URL=https://nasscan.home.example   # for links in notifications
```

With that set, login cookies get the `Secure` flag, and the lockout counts real client
addresses instead of the proxy's. The value is a comma-separated list of addresses or CIDRs.

**Caddy** (sends the forwarded headers by itself; `tls internal` uses Caddy's own CA for a
LAN-only name):

```caddyfile
nasscan.home.example {
    tls internal
    reverse_proxy <truenas-host>:8010
}
```

If the proxy runs on the TrueNAS host itself, publish the port on loopback only
(`NASSCAN_API_PUBLISH_PORT=127.0.0.1:8010`), so the LAN can reach the UI only through the
proxy.

## Reporting a problem

Open an issue on [GitHub](https://github.com/drewsum/nas_scanner/issues).
