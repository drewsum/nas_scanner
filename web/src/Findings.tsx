import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { api, type AllowlistEntry, type Finding, type FindingFilter } from "./api";
import { ENGINE_LABELS } from "./Engines";
import { ago, formatBytes, HashLinks, setQuery, VERDICT_CLASS, when, type Route } from "./util";

const STATUS_LABEL: Record<string, string> = {
  open: "Open",
  acknowledged: "Acknowledged",
  ignored: "Ignored",
  allowlisted: "Allowlisted",
  resolved: "Resolved",
};

const FILTERS: [FindingFilter, string][] = [
  ["active", "Open and acknowledged"],
  ["open", "Open"],
  ["acknowledged", "Acknowledged"],
  ["ignored", "Ignored"],
  ["allowlisted", "Allowlisted"],
  ["resolved", "Resolved"],
  ["all", "All"],
];

const label = (engine: string) => ENGINE_LABELS[engine] ?? engine;

function useInvalidate() {
  const client = useQueryClient();
  return () => {
    for (const key of ["findings", "finding", "finding-summary", "allowlist", "file"]) {
      void client.invalidateQueries({ queryKey: [key] });
    }
  };
}

/** The engines whose detections counted, strongest first. */
function flaggedBy(f: Finding): string {
  const engines = f.evidence.filter((e) => e.points > 0).map((e) => label(e.engine));
  return engines.join(", ") || "—";
}

function SummaryPills() {
  const summary = useQuery({ queryKey: ["finding-summary"], queryFn: api.findingSummary });
  const open = summary.data?.counts.open ?? {};
  return (
    <>
      {!!open.malicious && <span className="pill bad">{open.malicious} malicious</span>}
      {!!open.suspicious && <span className="pill warn">{open.suspicious} suspicious</span>}
      {!!summary.data?.pending && (
        <span className="muted small">{summary.data.pending} files waiting for a verdict</span>
      )}
    </>
  );
}

function FindingsTable({ rows }: { rows: Finding[] }) {
  return (
    <table className="stack">
      <thead>
        <tr>
          <th>File</th>
          <th>Verdict</th>
          <th>Flagged by</th>
          <th>Status</th>
          <th>Opened</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((f) => (
          <tr key={f.id}>
            <td className="mono wrap">
              <a href={`#/findings/${f.id}`}>{f.path}</a>
              {f.file_status === "removed" && <span className="muted"> (removed)</span>}
            </td>
            <td>
              <span className={VERDICT_CLASS[f.verdict]}>{f.verdict}</span>{" "}
              <span className="muted small" title="score">
                {f.score}
              </span>
            </td>
            <td data-label="By">{flaggedBy(f)}</td>
            <td>
              {STATUS_LABEL[f.status]}
              {f.resolution && <span className="muted"> ({f.resolution})</span>}
            </td>
            <td data-label="Opened" title={when(f.opened_at)}>
              {ago(f.opened_at)}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/** The dashboard's short list: what needs a look. */
export function OpenFindings() {
  const findings = useQuery({ queryKey: ["findings", "open", "", "", 10], queryFn: () => api.findings("open", "", "", 10) });
  return (
    <section className="card">
      <div className="card-head">
        <h2>Open findings</h2>
        <div className="actions">
          <SummaryPills />
          <a href="#/findings">All findings</a>
        </div>
      </div>
      {findings.error && <p className="error">{findings.error.message}</p>}
      {findings.data?.length === 0 && <p className="muted">Nothing flagged. All clear.</p>}
      {!!findings.data?.length && <FindingsTable rows={findings.data} />}
    </section>
  );
}

/** Every finding, filtered by status, verdict and path (kept in the address for sharing). */
export function FindingsPage({ route }: { route: Route }) {
  const [status, setStatus] = useState<FindingFilter>((route.query.get("status") as FindingFilter) || "active");
  const [verdict, setVerdict] = useState(route.query.get("verdict") ?? "");
  const [q, setQ] = useState(route.query.get("q") ?? "");
  const term = q.trim();
  const findings = useQuery({
    queryKey: ["findings", status, verdict, term],
    queryFn: () => api.findings(status, verdict, term, 500),
    placeholderData: (previous) => previous,
  });
  const update = (next: { status?: FindingFilter; verdict?: string; q?: string }) => {
    const s = { status, verdict, q, ...next };
    setStatus(s.status);
    setVerdict(s.verdict);
    setQ(s.q);
    setQuery("/findings", { status: s.status === "active" ? "" : s.status, verdict: s.verdict, q: s.q.trim() });
  };

  return (
    <div className="page">
      <section className="card">
        <div className="card-head">
          <h2>Findings</h2>
          <div className="actions">
            <SummaryPills />
          </div>
        </div>
        <div className="toolbar">
          <label className="visually-hidden" htmlFor="finding-q">
            Path contains
          </label>
          <input
            id="finding-q"
            className="search"
            type="search"
            value={q}
            onChange={(e) => update({ q: e.target.value })}
            placeholder="Path contains…"
          />
          <label className="visually-hidden" htmlFor="finding-status">
            Status
          </label>
          <select id="finding-status" value={status} onChange={(e) => update({ status: e.target.value as FindingFilter })}>
            {FILTERS.map(([value, text]) => (
              <option key={value} value={value}>
                {text}
              </option>
            ))}
          </select>
          <label className="visually-hidden" htmlFor="finding-verdict">
            Verdict
          </label>
          <select id="finding-verdict" value={verdict} onChange={(e) => update({ verdict: e.target.value })}>
            <option value="">Any verdict</option>
            <option value="malicious">Malicious</option>
            <option value="suspicious">Suspicious</option>
          </select>
        </div>
        {findings.error && <p className="error">{findings.error.message}</p>}
        {findings.data?.length === 0 && (
          <p className="muted">{status === "active" && !verdict && !term ? "Nothing flagged. All clear." : "None match."}</p>
        )}
        {!!findings.data?.length && <FindingsTable rows={findings.data} />}
        {findings.data?.length === 500 && <p className="muted small">Showing the first 500.</p>}
      </section>
    </div>
  );
}

/** One finding: why it was flagged, by whom, and what to do about it. */
export function FindingPage({ id }: { id: number }) {
  const finding = useQuery({ queryKey: ["finding", id], queryFn: () => api.finding(id) });
  const invalidate = useInvalidate();
  const [note, setNote] = useState<string | null>(null);
  const triage = useMutation({
    mutationFn: (status: "open" | "acknowledged" | "ignored") =>
      api.setFindingStatus(id, status, note ?? finding.data?.note ?? ""),
    onSuccess: () => {
      setNote(null);
      invalidate();
    },
  });
  const allow = useMutation({
    mutationFn: ({ kind, value }: { kind: AllowlistEntry["kind"]; value: string }) =>
      api.addAllowlist(kind, value, `From finding ${id}`),
    onSuccess: invalidate,
  });
  const f = finding.data;
  if (finding.error) return <p className="error">{finding.error.message}</p>;
  if (!f) return null;
  const error = triage.error ?? allow.error;
  const triageable = f.status === "open" || f.status === "acknowledged" || f.status === "ignored";
  const folder = f.path.includes("/") ? `${f.path.slice(0, f.path.lastIndexOf("/"))}/*` : null;

  return (
    <div className="page">
      <a href="#/findings" className="back">
        ← Findings
      </a>
      <div className="detail-head">
        <h1 className="mono wrap-anywhere">{f.path.split("/").pop()}</h1>
        <span>
          <span className={VERDICT_CLASS[f.verdict]}>{f.verdict}</span> <span className="muted">score {f.score}</span>
        </span>
      </div>
      {error && <p className="error">{error.message}</p>}
      <section className="card">
        <dl className="facts">
          <div>
            <dt>Path</dt>
            <dd className="mono">
              <a href={`#/files/${f.file_id}`}>{f.path}</a>
              {f.file_status === "removed" && <span className="muted"> (removed)</span>}
            </dd>
          </div>
          <div>
            <dt>Status</dt>
            <dd>
              {STATUS_LABEL[f.status]}
              {f.resolution && ` (${f.resolution === "removed" ? "file removed" : "no longer flagged"})`}
              <span className="muted"> since {when(f.status_changed_at)}</span>
            </dd>
          </div>
          <div>
            <dt>Type</dt>
            <dd>
              {f.mime ?? "unknown"}, {formatBytes(f.size)}
            </dd>
          </div>
          <div>
            <dt>SHA-256</dt>
            <dd className="mono">{f.sha256 ?? "not hashed (large media file read in part)"}</dd>
          </div>
          {f.sha256 && (
            <div>
              <dt>Look up</dt>
              <dd>
                <HashLinks sha256={f.sha256} />
              </dd>
            </div>
          )}
          <div>
            <dt>First flagged</dt>
            <dd>{when(f.first_seen)}</dd>
          </div>
          <div>
            <dt>Last flagged</dt>
            <dd>{when(f.last_seen)}</dd>
          </div>
        </dl>
      </section>

      <section className="card">
        <h2>Evidence</h2>
        <table className="stack">
          <thead>
            <tr>
              <th>Engine</th>
              <th>Severity</th>
              <th>Points</th>
              <th>What</th>
            </tr>
          </thead>
          <tbody>
            {f.evidence.map((e, i) => (
              <tr key={i}>
                <td>{label(e.engine)}</td>
                <td>{e.severity}</td>
                <td data-label="Points">{e.points || <span className="muted">0</span>}</td>
                <td className="wrap">
                  <span className="mono">{e.name}</span>
                  {e.description && e.description !== e.name && <> — {e.description}</>}
                  {e.member && <span className="muted mono"> in {e.member}</span>}
                  {e.link && (
                    <>
                      {" "}
                      <a href={e.link} target="_blank" rel="noreferrer noopener">
                        report
                      </a>
                    </>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="muted small">
          Each engine counts once, with its strongest detection. 40 points is suspicious, 100 malicious.
        </p>
      </section>

      <section className="card">
        <h2>Triage</h2>
        {triageable ? (
          <>
            <label className="visually-hidden" htmlFor="finding-note">
              Note
            </label>
            <textarea
              id="finding-note"
              rows={2}
              value={note ?? f.note ?? ""}
              onChange={(e) => setNote(e.target.value)}
              placeholder="Note (optional): why it's fine, what you did"
            />
            <div className="row">
              {f.status !== "acknowledged" && (
                <button type="button" disabled={triage.isPending} onClick={() => triage.mutate("acknowledged")}>
                  Acknowledge
                </button>
              )}
              {f.status !== "ignored" && (
                <button type="button" disabled={triage.isPending} onClick={() => triage.mutate("ignored")}>
                  Ignore (false positive)
                </button>
              )}
              {f.status !== "open" && (
                <button type="button" disabled={triage.isPending} onClick={() => triage.mutate("open")}>
                  Reopen
                </button>
              )}
              {note !== null && note !== (f.note ?? "") && (
                <button
                  type="button"
                  disabled={triage.isPending}
                  onClick={() => triage.mutate(f.status as "open" | "acknowledged" | "ignored")}
                >
                  Save note
                </button>
              )}
            </div>
            <p className="muted small">
              Acknowledged stays listed without alerting again, until it turns malicious or the file changes. Ignored
              stays quiet until the file&apos;s content changes.
            </p>
          </>
        ) : (
          <p className="muted">
            {f.status === "allowlisted" ? "On the allowlist." : "Resolved by the scanner."}
            {f.note && <> Note: {f.note}</>}
          </p>
        )}
        {f.status !== "allowlisted" && (
          <div className="row">
            {f.sha256 && (
              <button type="button" disabled={allow.isPending} onClick={() => allow.mutate({ kind: "sha256", value: f.sha256! })}>
                Allowlist this content
              </button>
            )}
            {folder && (
              <button type="button" disabled={allow.isPending} onClick={() => allow.mutate({ kind: "path", value: folder })}>
                Allowlist <span className="mono">{folder}</span>
              </button>
            )}
          </div>
        )}
      </section>
    </div>
  );
}

/** Content and paths that never raise a finding. */
export function AllowlistPanel() {
  const entries = useQuery({ queryKey: ["allowlist"], queryFn: api.allowlist });
  const invalidate = useInvalidate();
  const [kind, setKind] = useState<AllowlistEntry["kind"]>("path");
  const [value, setValue] = useState("");
  const [note, setNote] = useState("");
  const add = useMutation({
    mutationFn: () => api.addAllowlist(kind, value, note || undefined),
    onSuccess: () => {
      setValue("");
      setNote("");
      invalidate();
    },
  });
  const remove = useMutation({ mutationFn: api.deleteAllowlist, onSuccess: invalidate });

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (value.trim()) add.mutate();
  };

  return (
    <section className="card">
      <h2>Allowlist</h2>
      <p className="muted small">
        A SHA-256 matches that exact content anywhere. A path pattern is relative to the scan root, and * matches
        across folders: <span className="mono">Games/mods/*</span>.
      </p>
      {(add.error ?? remove.error) && <p className="error">{(add.error ?? remove.error)!.message}</p>}
      {entries.data?.length === 0 && <p className="muted">Empty.</p>}
      {!!entries.data?.length && (
        <table className="stack">
          <tbody>
            {entries.data.map((e) => (
              <tr key={e.id}>
                <td className="mono wrap">{e.value}</td>
                <td className="muted">{e.kind === "sha256" ? "content" : "path"}</td>
                <td>{e.note}</td>
                <td className="muted">{when(e.created_at)}</td>
                <td>
                  <button type="button" className="plain danger-text" onClick={() => remove.mutate(e.id)}>
                    Remove
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <form className="row" onSubmit={submit}>
        <label className="visually-hidden" htmlFor="allow-kind">
          Kind
        </label>
        <select id="allow-kind" value={kind} onChange={(e) => setKind(e.target.value as AllowlistEntry["kind"])}>
          <option value="path">Path pattern</option>
          <option value="sha256">SHA-256</option>
        </select>
        <label className="visually-hidden" htmlFor="allow-value">
          Value
        </label>
        <input
          id="allow-value"
          className="search mono"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder={kind === "path" ? "Downloads/tools/*" : "64 hex characters"}
        />
        <label className="visually-hidden" htmlFor="allow-note">
          Note
        </label>
        <input id="allow-note" value={note} onChange={(e) => setNote(e.target.value)} placeholder="Note (optional)" />
        <button type="submit" disabled={!value.trim() || add.isPending}>
          Add
        </button>
      </form>
    </section>
  );
}
