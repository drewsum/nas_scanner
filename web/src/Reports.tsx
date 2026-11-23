import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "./api";
import { when } from "./util";

function WeeklyReports() {
  const client = useQueryClient();
  const reports = useQuery({ queryKey: ["reports"], queryFn: api.reports });
  const make = useMutation({
    mutationFn: api.makeReport,
    onSuccess: () => void client.invalidateQueries({ queryKey: ["reports"] }),
  });
  return (
    <section className="card">
      <div className="card-head">
        <h2>Weekly reports</h2>
        <button type="button" disabled={make.isPending} onClick={() => make.mutate()}>
          Make one now
        </button>
      </div>
      <p className="muted small">
        Made after each scheduled full scan and kept here: scans, coverage, new and resolved findings, and what&apos;s
        still open.
      </p>
      {make.error && <p className="error">{make.error.message}</p>}
      {reports.data?.length === 0 && <p className="muted">None yet. The first comes after the weekly full scan.</p>}
      {!!reports.data?.length && (
        <table className="stack">
          <thead>
            <tr>
              <th>Week</th>
              <th>Scans</th>
              <th>New findings</th>
              <th>Open</th>
              <th>
                <span className="visually-hidden">Data</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {reports.data.map((r) => (
              <tr key={r.id}>
                <td>
                  <a href={`/api/reports/${r.id}`} target="_blank" rel="noopener">
                    {new Date(r.period_start).toLocaleDateString()} – {new Date(r.period_end).toLocaleDateString()}
                  </a>
                  {r.run_id === null && <span className="muted small"> (made by hand)</span>}
                </td>
                <td data-label="Scans">{r.scans}</td>
                <td data-label="New">
                  {(r.opened.malicious ?? 0) + (r.opened.suspicious ?? 0)}
                  {!!r.opened.malicious && <span className="error"> ({r.opened.malicious} malicious)</span>}
                </td>
                <td data-label="Open" className={r.open_findings ? "error" : undefined}>
                  {r.open_findings}
                </td>
                <td>
                  <a href={`/api/reports/${r.id}/data`} target="_blank" rel="noopener" className="small">
                    JSON
                  </a>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

const EXPORTS: [string, string, string][] = [
  ["findings", "Findings", "every finding, with its evidence and triage"],
  ["detections", "Detections", "each engine's and feed's raw detections"],
  ["runs", "Scan runs", "every scan and its totals"],
  ["files", "File inventory", "every file seen, with hashes (large)"],
  ["allowlist", "Allowlist", "hashes and path patterns"],
];

function Exports() {
  return (
    <section className="card">
      <h2>Export</h2>
      <ul className="exports">
        {EXPORTS.map(([name, label, what]) => (
          <li key={name}>
            <span>
              {label} <span className="muted small">{what}</span>
            </span>
            <span className="exports-links">
              <a href={`/api/export/${name}.csv`} download>
                CSV
              </a>
              <a href={`/api/export/${name}.json`} download>
                JSON
              </a>
            </span>
          </li>
        ))}
      </ul>
    </section>
  );
}

function Notifications() {
  const client = useQueryClient();
  const status = useQuery({ queryKey: ["notify"], queryFn: api.notifyStatus, refetchInterval: 60_000 });
  const test = useMutation({
    mutationFn: api.notifyTest,
    onSettled: () => void client.invalidateQueries({ queryKey: ["notify"] }),
  });
  const s = status.data;
  return (
    <section className="card">
      <div className="card-head">
        <h2>Notifications</h2>
        {s?.configured && (
          <button type="button" disabled={test.isPending} onClick={() => test.mutate()}>
            {test.isPending ? "Sending…" : "Send a test"}
          </button>
        )}
      </div>
      {s && !s.configured && (
        <p className="muted">
          Off. Set <span className="mono">NASSCAN_APPRISE_URLS</span> in the stack, for example{" "}
          <span className="mono">mailto://you:app-password@gmail.com</span>, to get alerts by email or any service
          Apprise knows.
        </p>
      )}
      {s?.configured && (
        <>
          <p>
            Sending to {s.services} service{s.services === 1 ? "" : "s"}: new {s.min_verdict === "malicious" ? "malicious" : "suspicious or malicious"}{" "}
            findings at once, failed scans
            {s.digest ? ", a summary after every scan" : ""}
            {s.weekly_report ? ", and the weekly report" : ""}. At most {s.max_per_hour} messages an hour.
          </p>
          {!s.links && (
            <p className="muted small">
              Set <span className="mono">NASSCAN_PUBLIC_URL</span> (how you open this page) to put links in the messages.
            </p>
          )}
        </>
      )}
      {test.data && (
        <p className={test.data.ok ? "notice" : "error"}>
          {test.data.ok ? "Sent. Check that it arrived." : `Couldn't send: ${test.data.error}`}
        </p>
      )}
      {test.error && <p className="error">{test.error.message}</p>}
      {!!s?.recent.length && (
        <table className="stack">
          <thead>
            <tr>
              <th>Message</th>
              <th>Kind</th>
              <th>Sent</th>
              <th>Result</th>
            </tr>
          </thead>
          <tbody>
            {s.recent.map((n) => (
              <tr key={n.id} title={n.body}>
                <td>{n.title.replace(/^nasscan: /, "")}</td>
                <td data-label="Kind" className="muted">
                  {n.kind}
                </td>
                <td data-label="Sent">{when(n.created_at)}</td>
                <td className={n.ok ? undefined : "error"}>{n.ok ? "sent" : `failed: ${n.error}`}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

export function ReportsPage() {
  return (
    <div className="page">
      <WeeklyReports />
      <Notifications />
      <Exports />
    </div>
  );
}
