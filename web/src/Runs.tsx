import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { api, type RunKind, type ScanRun } from "./api";
import { formatBytes, when } from "./util";

function duration(run: ScanRun): string {
  if (!run.started_at) return "";
  const end = run.finished_at ? new Date(run.finished_at) : new Date();
  const s = Math.max(0, Math.round((end.getTime() - new Date(run.started_at).getTime()) / 1000));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`;
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
}

export const RUN_STATUS_CLASS: Record<string, string> = {
  completed: "pill ok",
  failed: "pill bad",
  running: "pill run",
  queued: "pill run",
  cancelled: "pill muted-pill",
};

export const isActive = (r: ScanRun) => r.status === "running" || r.status === "queued";

/** Recent runs, polled every 3 s while one is active. */
export function useRuns(limit: number) {
  return useQuery({
    queryKey: ["runs", limit],
    queryFn: () => api.runs(limit),
    refetchInterval: (q) => (q.state.data?.some(isActive) ? 3000 : 30_000),
  });
}

function useRefreshRuns() {
  const client = useQueryClient();
  return () => {
    void client.invalidateQueries({ queryKey: ["runs"] });
    void client.invalidateQueries({ queryKey: ["run"] });
  };
}

function Progress({ run }: { run: ScanRun }) {
  const refresh = useRefreshRuns();
  const cancel = useMutation({ mutationFn: api.cancelRun, onSettled: refresh });
  return (
    <p className="notice">
      <a href={`#/scans/${run.id}`}>Scan {run.id}</a> ({run.kind}
      {run.root && <span className="mono"> {run.root}</span>}) is {run.status}
      {run.status === "running" &&
        `: ${run.files_seen.toLocaleString()} files seen, ${run.files_hashed.toLocaleString()} read (${formatBytes(run.bytes_hashed)})`}
      {run.current_path && (
        <>
          {" "}
          — <span className="mono wrap-anywhere">{run.current_path}</span>
        </>
      )}{" "}
      <button type="button" className="plain link-button" onClick={() => cancel.mutate(run.id)}>
        Cancel
      </button>
    </p>
  );
}

/** Scan now: new and changed files, everything, or one folder. Off while a scan is active. */
export function ScanControls() {
  const runs = useRuns(20);
  const refresh = useRefreshRuns();
  const [folder, setFolder] = useState("");
  const start = useMutation({
    mutationFn: ({ kind, path }: { kind: RunKind; path?: string }) => api.startRun(kind, path),
    onSuccess: () => setFolder(""),
    onSettled: refresh,
  });
  const active = runs.data?.find(isActive);
  const busy = !!active || start.isPending;
  const scanFolder = (e: FormEvent) => {
    e.preventDefault();
    if (folder.trim()) start.mutate({ kind: "path", path: folder.trim() });
  };

  return (
    <section className="card">
      <div className="card-head">
        <h2>Scan now</h2>
        <div className="actions">
          <button type="button" disabled={busy} onClick={() => start.mutate({ kind: "incremental" })}>
            New and changed files
          </button>
          <button type="button" disabled={busy} onClick={() => start.mutate({ kind: "full" })}>
            Everything
          </button>
        </div>
      </div>
      <form className="row" onSubmit={scanFolder}>
        <label className="visually-hidden" htmlFor="scan-folder">
          Folder to scan
        </label>
        <input
          id="scan-folder"
          className="search mono"
          value={folder}
          onChange={(e) => setFolder(e.target.value)}
          placeholder="One folder, relative to the scan root: Downloads/2026"
        />
        <button type="submit" disabled={busy || !folder.trim()}>
          Scan folder
        </button>
      </form>
      {start.error && <p className="error">{start.error.message}</p>}
      {active ? (
        <Progress run={active} />
      ) : (
        <p className="muted small">
          Scheduled scans read new and changed files nightly and everything weekly. A folder scan reads every file in
          it.
        </p>
      )}
    </section>
  );
}

/** Scan history: a short list for the dashboard, or the whole page. */
export function RunsTable({ limit = 20, title = "Scans" }: { limit?: number; title?: string }) {
  const runs = useRuns(limit);
  return (
    <section className="card">
      <div className="card-head">
        <h2>{title}</h2>
        {limit < 50 && <a href="#/scans">All scans</a>}
      </div>
      {runs.data?.length === 0 && <p className="muted">No scans yet. The first scheduled one runs tonight.</p>}
      {!!runs.data?.length && (
        <table className="stack">
          <thead>
            <tr>
              <th>Scan</th>
              <th>Status</th>
              <th>Started</th>
              <th>Took</th>
              <th>Files</th>
              <th>New</th>
              <th>Changed</th>
              <th>Removed</th>
              <th>Read</th>
              <th>Flagged</th>
              <th>Errors</th>
            </tr>
          </thead>
          <tbody>
            {runs.data.map((r) => (
              <tr key={r.id} title={r.message ?? r.last_error ?? undefined}>
                <td>
                  <a href={`#/scans/${r.id}`}>
                    #{r.id} {r.kind}
                  </a>
                  {r.root && <span className="muted mono"> {r.root}</span>}
                </td>
                <td>
                  <span className={RUN_STATUS_CLASS[r.status] ?? "pill"}>{r.status}</span>
                  {r.resumed > 0 && <span className="muted"> (resumed)</span>}
                </td>
                <td data-label="Started">{when(r.started_at ?? r.requested_at)}</td>
                <td data-label="Took">{duration(r)}</td>
                <td data-label="Files">{r.files_seen.toLocaleString()}</td>
                <td data-label="New">{r.files_new.toLocaleString()}</td>
                <td data-label="Changed">{r.files_changed.toLocaleString()}</td>
                <td data-label="Removed">{r.files_removed.toLocaleString()}</td>
                <td data-label="Read">{formatBytes(r.bytes_hashed)}</td>
                <td data-label="Flagged" className={r.files_flagged ? "error" : undefined}>
                  {r.files_flagged.toLocaleString()}
                </td>
                <td data-label="Errors" className={r.errors ? "error" : undefined}>
                  {r.errors.toLocaleString()}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

export function RunsPage() {
  return (
    <div className="page">
      <ScanControls />
      <RunsTable limit={100} title="Scan history" />
    </div>
  );
}

/** One run: its totals, live progress, and what it couldn't read. */
export function RunPage({ id }: { id: number }) {
  const run = useQuery({
    queryKey: ["run", id],
    queryFn: () => api.run(id),
    refetchInterval: (q) => (q.state.data && isActive(q.state.data) ? 3000 : false),
  });
  const active = !!run.data && isActive(run.data);
  const errors = useQuery({
    queryKey: ["run-errors", id],
    queryFn: () => api.runErrors(id),
    refetchInterval: active ? 10_000 : false,
  });
  const r = run.data;
  if (run.error) return <p className="error">{run.error.message}</p>;
  if (!r) return null;
  const facts: [string, string][] = [
    ["Kind", r.kind + (r.root ? ` of ${r.root}` : "")],
    ["Started by", r.trigger === "manual" ? "you" : "the schedule"],
    ["Requested", when(r.requested_at)],
    ["Started", when(r.started_at)],
    ["Finished", when(r.finished_at)],
    ["Took", duration(r)],
    ["Files seen", r.files_seen.toLocaleString()],
    ["New", r.files_new.toLocaleString()],
    ["Changed", r.files_changed.toLocaleString()],
    ["Unchanged", r.files_unchanged.toLocaleString()],
    ["Removed", r.files_removed.toLocaleString()],
    ["Read", `${r.files_hashed.toLocaleString()} files, ${formatBytes(r.bytes_hashed)} of ${formatBytes(r.bytes_seen)}`],
    ["Flagged", `${r.files_flagged.toLocaleString()} files, ${r.detections.toLocaleString()} detections`],
    ["Errors", r.errors.toLocaleString()],
  ];
  if (r.resumed) facts.push(["Resumed", `${r.resumed} times`]);
  return (
    <div className="page">
      <a href="#/scans" className="back">
        ← Scans
      </a>
      <div className="detail-head">
        <h1>
          Scan {r.id} <span className={RUN_STATUS_CLASS[r.status] ?? "pill"}>{r.status}</span>
        </h1>
        <a href={`/api/runs/${r.id}/report`} target="_blank" rel="noopener">
          Printable report
        </a>
      </div>
      {active && <Progress run={r} />}
      {r.message && <p className={r.status === "failed" ? "error" : "muted"}>{r.message}</p>}
      <section className="card">
        <dl className="facts cols">
          {facts.map(([k, v]) => (
            <div key={k}>
              <dt>{k}</dt>
              <dd>{v}</dd>
            </div>
          ))}
        </dl>
      </section>
      <section className="card">
        <h2>Couldn&apos;t read</h2>
        {errors.data?.length === 0 && <p className="muted">Nothing. Every file was read.</p>}
        {!!errors.data?.length && (
          <>
            {r.errors > errors.data.length && (
              <p className="muted small">
                The first {errors.data.length} of {r.errors.toLocaleString()}.
              </p>
            )}
            <table className="stack">
              <thead>
                <tr>
                  <th>Path</th>
                  <th>Why</th>
                  <th>When</th>
                </tr>
              </thead>
              <tbody>
                {errors.data.map((e) => (
                  <tr key={e.id}>
                    <td className="mono wrap">{e.path || "/"}</td>
                    <td>{e.message}</td>
                    <td className="muted">{when(e.at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p className="muted small">
              The scanner skips folders it can&apos;t open and never marks the files in them removed. It runs as uid
              10001, so a folder only its owner can read (chmod 700) is out of its reach.
            </p>
          </>
        )}
      </section>
    </div>
  );
}
