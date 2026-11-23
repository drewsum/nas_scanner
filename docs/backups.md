# Backups and restore

## What's backed up

The `backup` service dumps the database with `pg_dump` once a day into
`<NASSCAN_DATA_DIR>/backups`: the file inventory and its hashes, scan history, detections,
findings and their triage (acknowledged, ignored, notes), the allowlist, threat-intel answers
and quota use, reports and the notification log.

**Not in the dumps:**
- **The downloaded hash feeds** (MalwareBazaar, ThreatFox, VirusShare: millions of rows).
  After a restore the scanner downloads them again.
- **The stack's environment variables** (passwords, API keys, Apprise URLs). Keep a copy of
  those somewhere safe, such as a password manager.

Details:
- **Names.** Files are named for when they were made, e.g. `nasscan-20261123T020000Z.dump`
  (UTC), in pg_dump's compressed custom format.
- **When.** A dump is made when the newest is older than `NASSCAN_BACKUP_INTERVAL_HOURS` (24),
  so restarting the stack doesn't add extra ones.
- **How many.** The newest `NASSCAN_BACKUP_KEEP` (14) are kept; older ones are deleted.
- **Who can read them.** The directory and files are readable by the nasscan user (uid 10001)
  only.
- **Health.** Each run's result shows under **Status** as *Database backup*. A failed backup is
  tried again an hour later. A notification goes out if it keeps failing, or if no backup has
  been made for two intervals (the backup container stopped), and another when it works again.

The dumps sit on the same pool as the database. To survive losing the pool, include the
dataset in a TrueNAS replication or cloud sync task. ZFS snapshots of the dataset are a good
extra layer, but a snapshot of a running database's files is only crash-consistent; the dumps
are the clean copy.

### A backup now

```sh
sudo docker exec -u nasscan nas_scanner-backup-1 nasscan backup --once
```

Portainer names the containers after the stack, here `nas_scanner`; `sudo docker ps` lists them.
With plain compose, `sudo docker compose exec -u nasscan backup nasscan backup --once`.

## Restoring

A restore **replaces** the database with the dump's contents. Everything recorded since that
dump is lost, so take a fresh backup first if the current data is worth anything. A dump from
an older nas_scanner is fine: the restore runs the migrations afterwards.

1. **Stop the api and scanner,** so nothing writes while the database is replaced. The restore
   refuses to start while anything else is connected.

   ```sh
   sudo docker stop nas_scanner-api-1 nas_scanner-scanner-1
   ```

2. **Pick a dump** and restore it from the backup container, as the nasscan user. (The
   container's root has no capabilities and can't read the files.)

   ```sh
   sudo docker exec -u nasscan nas_scanner-backup-1 ls -l /backups
   sudo docker exec -u nasscan nas_scanner-backup-1 nasscan restore /backups/nasscan-20261123T020000Z.dump --yes
   ```

   It drops and recreates the database, restores the dump, then runs the migrations, and
   stops at the first error with what failed. Without `--yes` it only says what it would do.

3. **Start them again:**

   ```sh
   sudo docker start nas_scanner-scanner-1 nas_scanner-api-1
   ```

   The scanner downloads the hash feeds again within a few minutes.

To restore a dump from elsewhere, copy it into `<NASSCAN_DATA_DIR>/backups` first and make it
readable by uid 10001 (`chown 10001` it).

### Trying a dump without touching the live data

`--database` restores into a separate database instead. It's created (or replaced) and then
left alone; the app keeps running on its own. Look around with `psql`, then drop it:

```sh
sudo docker exec -u nasscan nas_scanner-backup-1 nasscan restore /backups/<file> --database nasscan_restore_test
sudo docker exec nas_scanner-db-1 psql -U <POSTGRES_USER> -d nasscan_restore_test -c "SELECT count(*) FROM files"
sudo docker exec nas_scanner-db-1 psql -U <POSTGRES_USER> -d postgres -c "DROP DATABASE nasscan_restore_test WITH (FORCE)"
```

## Exports

**Reports → Export** has CSV and JSON of findings, detections, scans, the file inventory and
the allowlist ([notifications.md](notifications.md#exports)). They're for spreadsheets and
other tools, not for restoring: use the dumps for that.
