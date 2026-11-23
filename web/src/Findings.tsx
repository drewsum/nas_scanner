import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Fragment, useState, type FormEvent } from "react";
import { api, type AllowlistEntry, type Finding, type FindingFilter } from "./api";
import { ago, ENGINE_LABELS } from "./Engines";

const VERDICT_CLASS: Record<string, string> = {
  malicious: "pill bad",
  suspicious: "pill warn",
};

const STATUS_LABEL: Record<string, string> = {
  open: "Open",
  acknowledged: "Acknowledged",
  ignored: "Ignored",
  allowlisted: "Allowlisted",
  resolved: "Resolved",
};

const FILTERS: [FindingFilter, string][] = [
  ["active", "Open and acknowledged"],
  ["ignored", "Ignored"],
  ["allowlisted", "Allowlisted"],
  ["resolved", "Resolved"],
  ["all", "All"],
];

const label = (engine: string) => ENGINE_LABELS[engine] ?? engine;

function useInvalidate() {
  const client = useQueryClient();
  return () => {
    void client.invalidateQueries({ queryKey: ["findings"] });
    void client.invalidateQueries({ queryKey: ["finding-summary"] });
    void client.invalidateQueries({ queryKey: ["allowlist"] });
  };
}

/** One verdict per flagged file, with triage: acknowledge, ignore, reopen, allowlist. */
export function FindingsPanel() {
  const [filter, setFilter] = useState<FindingFilter>("active");
  const [expanded, setExpanded] = useState<number | null>(null);
  const findings = useQuery({
    queryKey: ["findings", filter],
    queryFn: () => api.findings(filter),
    refetchInterval: 30_000,
  });
  const summary = useQuery({ queryKey: ["finding-summary"], queryFn: api.findingSummary, refetchInterval: 30_000 });
  const invalidate = useInvalidate();
  const triage = useMutation({
    mutationFn: ({ id, status }: { id: number; status: "open" | "acknowledged" | "ignored" }) =>
      api.setFindingStatus(id, status),
    onSuccess: invalidate,
  });
  const allow = useMutation({
    mutationFn: (sha256: string) => api.addAllowlist("sha256", sha256),
    onSuccess: invalidate,
  });

  const open = summary.data?.counts.open ?? {};
  const error = findings.error ?? triage.error ?? allow.error;

  return (
    <section className="card">
      <div className="card-head">
        <h2>Findings</h2>
        <div className="actions">
          {!!open.malicious && <span className="pill bad">{open.malicious} malicious</span>}
          {!!open.suspicious && <span className="pill warn">{open.suspicious} suspicious</span>}
          {!!summary.data?.pending && (
            <span className="muted small">{summary.data.pending} files waiting for a verdict</span>
          )}
          <label className="visually-hidden" htmlFor="finding-filter">
            Show
          </label>
          <select id="finding-filter" value={filter} onChange={(e) => setFilter(e.target.value as FindingFilter)}>
            {FILTERS.map(([value, text]) => (
              <option key={value} value={value}>
                {text}
              </option>
            ))}
          </select>
        </div>
      </div>
      {error && <p className="error">{error.message}</p>}
      {findings.data?.length === 0 && (
        <p className="muted">{filter === "active" ? "Nothing flagged. All clear." : "None."}</p>
      )}
      {!!findings.data?.length && (
        <table className="stack">
          <thead>
            <tr>
              <th>Verdict</th>
              <th>File</th>
              <th>Flagged by</th>
              <th>Status</th>
              <th>First seen</th>
              <th>
                <span className="visually-hidden">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {findings.data.map((f) => (
              <Fragment key={f.id}>
                <tr>
                  <td>
                    <span className={VERDICT_CLASS[f.verdict]}>{f.verdict}</span>{" "}
                    <span className="muted small" title="score">
                      {f.score}
                    </span>
                  </td>
                  <td className="mono wrap">
                    {f.path}
                    {f.file_status === "removed" && <span className="muted"> (removed)</span>}
                  </td>
                  <td>{flaggedBy(f)}</td>
                  <td>
                    {STATUS_LABEL[f.status]}
                    {f.resolution && <span className="muted"> ({f.resolution})</span>}
                  </td>
                  <td title={new Date(f.first_seen).toLocaleString()}>{ago(f.first_seen)}</td>
                  <td>
                    <div className="actions">
                      {f.status === "open" && (
                        <>
                          <button type="button" onClick={() => triage.mutate({ id: f.id, status: "acknowledged" })}>
                            Acknowledge
                          </button>
                          <button type="button" onClick={() => triage.mutate({ id: f.id, status: "ignored" })}>
                            Ignore
                          </button>
                        </>
                      )}
                      {(f.status === "acknowledged" || f.status === "ignored") && (
                        <button type="button" onClick={() => triage.mutate({ id: f.id, status: "open" })}>
                          Reopen
                        </button>
                      )}
                      <button
                        type="button"
                        className="plain link-button"
                        aria-expanded={expanded === f.id}
                        onClick={() => setExpanded(expanded === f.id ? null : f.id)}
                      >
                        {expanded === f.id ? "Hide" : "Details"}
                      </button>
                    </div>
                  </td>
                </tr>
                {expanded === f.id && (
                  <tr>
                    <td colSpan={6}>
                      <FindingDetail
                        finding={f}
                        onAllowlist={f.sha256 && f.status !== "allowlisted" ? () => allow.mutate(f.sha256!) : undefined}
                      />
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

/** The engines whose detections counted, strongest first. */
function flaggedBy(f: Finding): string {
  const engines = f.evidence.filter((e) => e.points > 0).map((e) => label(e.engine));
  return engines.join(", ") || "—";
}

function FindingDetail({ finding, onAllowlist }: { finding: Finding; onAllowlist?: () => void }) {
  return (
    <div className="detail">
      <dl className="facts">
        <div>
          <dt>SHA-256</dt>
          <dd className="mono">{finding.sha256 ?? "not hashed (large media file)"}</dd>
        </div>
        <div>
          <dt>Type</dt>
          <dd>
            {finding.mime ?? "unknown"}, {finding.size.toLocaleString()} bytes
          </dd>
        </div>
        <div>
          <dt>Last flagged</dt>
          <dd>{new Date(finding.last_seen).toLocaleString()}</dd>
        </div>
        {finding.note && (
          <div>
            <dt>Note</dt>
            <dd>{finding.note}</dd>
          </div>
        )}
      </dl>
      <table>
        <thead>
          <tr>
            <th>Engine</th>
            <th>Severity</th>
            <th>Points</th>
            <th>What</th>
          </tr>
        </thead>
        <tbody>
          {finding.evidence.map((e, i) => (
            <tr key={i}>
              <td>{label(e.engine)}</td>
              <td>{e.severity}</td>
              <td>{e.points || <span className="muted">0</span>}</td>
              <td className="wrap">
                {e.description ?? e.name}
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
      {onAllowlist && (
        <div className="actions">
          <button type="button" onClick={onAllowlist}>
            Allowlist this content
          </button>
          <span className="muted small">Every copy of this exact file, anywhere on the NAS, stops being flagged.</span>
        </div>
      )}
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
      {!!entries.data?.length && (
        <table className="stack">
          <tbody>
            {entries.data.map((e) => (
              <tr key={e.id}>
                <td className="mono wrap">{e.value}</td>
                <td className="muted">{e.kind === "sha256" ? "content" : "path"}</td>
                <td>{e.note}</td>
                <td>
                  <button type="button" className="plain danger" onClick={() => remove.mutate(e.id)}>
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
