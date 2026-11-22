import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type RunKind, type ScanRun } from "./api";

export function formatBytes(n: number): string {
  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i++;
  }
  return `${n.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

function when(iso: string | null): string {
  return iso ? new Date(iso).toLocaleString() : "";
}

function duration(run: ScanRun): string {
  if (!run.started_at) return "";
  const end = run.finished_at ? new Date(run.finished_at) : new Date();
  const s = Math.max(0, Math.round((end.getTime() - new Date(run.started_at).getTime()) / 1000));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`;
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
}

const STATUS_CLASS: Record<string, string> = {
  completed: "pill ok",
  failed: "pill bad",
  running: "pill run",
  queued: "pill run",
  cancelled: "pill muted-pill",
};

/** Recent scans with live progress (polled every 3 s while one is active). */
export function RunsPanel() {
  const client = useQueryClient();
  const runs = useQuery({
    queryKey: ["runs"],
    queryFn: api.runs,
    refetchInterval: (q) =>
      q.state.data?.some((r) => r.status === "running" || r.status === "queued") ? 3000 : 30_000,
  });
  const refresh = () => void client.invalidateQueries({ queryKey: ["runs"] });
  const start = useMutation({ mutationFn: (kind: RunKind) => api.startRun(kind), onSettled: refresh });
  const cancel = useMutation({ mutationFn: api.cancelRun, onSettled: refresh });
  const active = runs.data?.find((r) => r.status === "running" || r.status === "queued");

  return (
    <section className="card">
      <div className="card-head">
        <h2>Scans</h2>
        <div className="actions">
          <button type="button" disabled={!!active || start.isPending} onClick={() => start.mutate("incremental")}>
            Scan changes now
          </button>
          <button type="button" disabled={!!active || start.isPending} onClick={() => start.mutate("full")}>
            Full scan now
          </button>
        </div>
      </div>
      {start.error && <p className="error">{start.error.message}</p>}
      {active && (
        <p className="notice">
          Scan {active.id} ({active.kind}) is {active.status}
          {active.status === "running" &&
            `: ${active.files_seen.toLocaleString()} files seen, ${active.files_hashed.toLocaleString()} read (${formatBytes(active.bytes_hashed)})`}
          {active.current_path && (
            <>
              {" "}
              — <span className="mono">{active.current_path}</span>
            </>
          )}{" "}
          <button type="button" className="plain" onClick={() => cancel.mutate(active.id)}>
            Cancel
          </button>
        </p>
      )}
      {runs.data?.length === 0 && <p className="muted">No scans yet. The first scheduled one runs tonight.</p>}
      {!!runs.data?.length && (
        <table>
          <thead>
            <tr>
              <th>#</th>
              <th>Kind</th>
              <th>Status</th>
              <th>Started</th>
              <th>Took</th>
              <th>Files</th>
              <th>New</th>
              <th>Changed</th>
              <th>Removed</th>
              <th>Read</th>
              <th>Errors</th>
            </tr>
          </thead>
          <tbody>
            {runs.data.map((r) => (
              <tr key={r.id} title={r.message ?? r.last_error ?? undefined}>
                <td>{r.id}</td>
                <td>
                  {r.kind}
                  {r.root && <span className="muted mono"> {r.root}</span>}
                </td>
                <td>
                  <span className={STATUS_CLASS[r.status] ?? "pill"}>{r.status}</span>
                  {r.resumed > 0 && <span className="muted"> (resumed)</span>}
                </td>
                <td>{when(r.started_at ?? r.requested_at)}</td>
                <td>{duration(r)}</td>
                <td>{r.files_seen.toLocaleString()}</td>
                <td>{r.files_new.toLocaleString()}</td>
                <td>{r.files_changed.toLocaleString()}</td>
                <td>{r.files_removed.toLocaleString()}</td>
                <td>{formatBytes(r.bytes_hashed)}</td>
                <td className={r.errors ? "error" : undefined}>{r.errors.toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
