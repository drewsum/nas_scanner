# Verdicts and findings

Every file with at least one detection gets a verdict: **clean**, **suspicious** or
**malicious**, with a score. A suspicious or malicious file becomes a **finding** on the
dashboard.

## Scoring

Detections come from the local engines (ClamAV, YARA, heuristics, documents, 3D print files),
the hash feeds (MalwareBazaar, ThreatFox, VirusShare, your own) and the live lookups (CIRCL,
Team Cymru, VirusTotal, ...). Each has a severity:

| Severity | Points |
|---|---|
| malicious | 100 |
| suspicious | 40 |
| info | 5 |

1. **Each engine or provider counts once,** with the points of its most severe detection. A
   YARA ruleset matching ten rules on one file is one opinion, not ten.
2. **Weights.** Those points are multiplied by the engine's weight, 1 unless
   `NASSCAN_VERDICT_WEIGHTS` says otherwise.
3. **Sum.** The score is the sum over engines.
4. **Known good.** If a known-good list (NSRL, via CIRCL) holds the file's hash and no detection
   is malicious, the score is multiplied by `NASSCAN_VERDICT_KNOWN_GOOD_FACTOR` (0.5). A
   heuristic hit on a stock Windows DLL then stays quiet. A real antivirus or feed hit is never
   softened.
5. **Verdict.** A score of at least `NASSCAN_VERDICT_MALICIOUS_SCORE` (100) is malicious; at
   least `NASSCAN_VERDICT_SUSPICIOUS_SCORE` (40) is suspicious; anything lower is clean.

What that means with the defaults:

| Evidence | Score | Verdict |
|---|---|---|
| ClamAV signature, a feed listing, or one malicious lookup | 100 | malicious |
| One heuristic (say a double extension) | 40 | suspicious |
| Two engines saying suspicious | 80 | suspicious |
| Three engines saying suspicious | 120 | malicious |
| Info-only detections (a PDF with JavaScript) | 5 each | clean |
| One heuristic, but the hash is in NSRL | 20 | clean |

### Tuning

- **Weights** go in `NASSCAN_VERDICT_WEIGHTS` as `engine=weight`, comma separated. The engine
  names are those on the dashboard's engine and threat-intel panels: `clamav`, `yara`,
  `heuristics`, `documents`, `printing`, `malwarebazaar-feed`, `threatfox-feed`,
  `virusshare-feed`, `circl`, `cymru`, `malwarebazaar`, `yaraify`, `virustotal`,
  `hybrid-analysis`, `metadefender`, `otx`, `opentip`.
- **Examples:** `heuristics=0.5` takes a lone heuristic below suspicious. `virustotal=1.5`
  makes a suspicious VirusTotal answer count 60. A weight of 0 makes an engine's detections
  show as evidence but never count.
- **When changes apply:** every flagged file is re-scored when the scanner restarts, so weight
  and threshold changes apply on the next deploy.

## Finding lifecycle

| Status | Meaning | Set by |
|---|---|---|
| Open | Needs a look. | New findings; reopened ones |
| Acknowledged | Seen, keep it listed, don't alert again. | You |
| Ignored | A false positive for this exact content. | You |
| Allowlisted | Its hash or path is on the allowlist. | The allowlist |
| Resolved | The file was removed, or its detections went away (clean). | The scanner |

- **An acknowledged finding reopens** if it escalates from suspicious to malicious, or if the
  file's content changes.
- **An ignored finding stays ignored** while the content stays the same. New content (a
  different SHA-256) starts over as open.
- **A resolved finding reopens** if the file is flagged again. Its first-seen date is kept.
- **Reopening by hand:** you can reopen an acknowledged or ignored finding at any time.

Verdicts follow the evidence within seconds. Database triggers queue a file whenever any of
these change:
- its detections (from a scan, a feed update, a new lookup answer, or a feed being turned off)
- its status
- its content

So a feed that starts listing a hash a year after the file arrived flags it at the next feed
refresh, with no rescan. A feed that drops the hash resolves the finding.

## Allowlist

On the dashboard's **Allowlist** panel, or the **Allowlist this content** button in a finding's
details:

- **SHA-256**: that exact content, wherever it is on the NAS, under any name.
- **Path pattern**: a glob relative to the scan root. `*` also matches `/`, so `Games/mods/*`
  covers everything below that folder, and `*.iso` covers every ISO.

Matching findings become *allowlisted* at once, and new matches never open. Removing an entry
reopens what it covered, if those files are still flagged.

## API

- `GET /api/findings?status=active|open|acknowledged|ignored|allowlisted|resolved|all&verdict=`
- `GET /api/findings/summary`: counts by status and verdict, plus files waiting for a verdict.
- `GET /api/findings/{id}`
- `POST /api/findings/{id}/status` with `{"status": "open|acknowledged|ignored", "note": "..."}`
- `GET /api/allowlist`
- `POST /api/allowlist` with `{"kind": "sha256|path", "value": "...", "note": "..."}`
- `DELETE /api/allowlist/{id}`
