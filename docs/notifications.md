# Notifications, reports and exports

## Notifications

NAS Scanner sends messages through [Apprise](https://github.com/caronc/apprise/wiki), so email
and most chat and push services work. Set the URLs in the stack's environment.

| Variable | Default | What it does |
|---|---|---|
| `NASSCAN_APPRISE_URLS` | *(off)* | Where to send, comma separated |
| `NASSCAN_PUBLIC_URL` | *(none)* | How you open the app (`http://nas:8010`), for links in messages |
| `NASSCAN_NOTIFY_MIN_VERDICT` | `suspicious` | Alert on new findings at least this bad: `suspicious` or `malicious` |
| `NASSCAN_NOTIFY_MAX_PER_HOUR` | `6` | Messages in any hour; more wait and go out together |
| `NASSCAN_NOTIFY_DIGEST` | `false` | A summary after every finished scan |
| `NASSCAN_NOTIFY_WEEKLY_REPORT` | `true` | Send the weekly report when it's made |

### Email

With Gmail, create an [app password](https://myaccount.google.com/apppasswords) (it needs
2-step verification), then:

```
NASSCAN_APPRISE_URLS=mailto://you:abcdefghijklmnop@gmail.com
```

To send somewhere else, add `?to=other@example.com`. For other providers, see Apprise's
[email page](https://github.com/caronc/apprise/wiki/Notify_email). Then open **Reports** in the
web UI and press **Send a test**. It shows whether delivery worked, and why not if it didn't.

### What gets sent

- **New findings,** as soon as their verdict lands (within about a minute of the scan reading
  the file). Everything waiting goes out in one message: path, verdict, score, the engines
  that flagged it and the SHA-256, with a link to the finding.
- **Each finding alerts once per opening.** Acknowledging or ignoring it, or the next scan
  seeing it again, sends nothing. If it reopens (it escalates, its content changes, or you
  reopen it), it alerts again.
- **Failed scans,** always.
- **A digest after every scan,** if `NASSCAN_NOTIFY_DIGEST=true`.
- **The weekly report,** after the scheduled full scan.
- **Health problems:** ClamAV, YARA or the database backup failing for half an hour, or no
  backup for two backup intervals (the backup container stopped). Once per problem, and
  again when it's fixed. The **Status** page shows the details.

### Limits

- **Hourly cap:** at most `NASSCAN_NOTIFY_MAX_PER_HOUR` messages in any hour. Failed tries count
  too, so a broken mail server isn't hammered. Anything over the cap waits and goes out
  together.
- **Stale alerts:** anything still unsent after two days is dropped.
- **What's sent:** paths, verdicts and engine names. Never file contents.

## Reports

- **Per scan:** each scan's page has a **Printable report** link. It covers the scan's totals,
  what it flagged, what it couldn't read, and the engine and feed versions it ran with
  (recorded when the scan finished).
- **Weekly:** made after each scheduled full scan, about 30 seconds after the scan's last
  verdicts are in. It covers the seven days before it: scans, coverage (how many files were
  read), findings opened and resolved, and everything still open or acknowledged.
  - Reports are kept, and listed under **Reports**.
  - **Make one now** creates one by hand. It isn't sent.
  - A report's **JSON** link gives its figures.

## Exports

**Reports → Export** downloads CSV or JSON of:
- findings
- detections
- scan runs
- the whole file inventory (streamed, so it works with millions of files)
- the allowlist

The same data is available from the API at `/api/export/<name>.csv` or `.json`.
