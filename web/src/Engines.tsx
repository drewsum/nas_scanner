import { useQuery } from "@tanstack/react-query";
import { api, type Severity } from "./api";

const ENGINE_LABELS: Record<string, string> = {
  clamav: "ClamAV",
  yara: "YARA",
  heuristics: "Heuristics",
  documents: "Documents",
  printing: "3D print files",
};

function age(iso: string | null): string {
  if (!iso) return "";
  const hours = (Date.now() - new Date(iso).getTime()) / 3_600_000;
  if (hours < 1) return "under an hour old";
  if (hours < 48) return `${Math.round(hours)} h old`;
  return `${Math.round(hours / 24)} days old`;
}

const STATUS_CLASS: Record<string, string> = {
  ok: "pill ok",
  warning: "pill warn",
  error: "pill bad",
  disabled: "pill muted-pill",
};

/** Each engine's health and how fresh its signatures are. */
export function EnginesPanel() {
  const engines = useQuery({ queryKey: ["engines"], queryFn: api.engines, refetchInterval: 60_000 });
  return (
    <section className="card">
      <h2>Engines</h2>
      {engines.data?.length === 0 && <p className="muted">The scanner hasn't reported yet.</p>}
      {!!engines.data?.length && (
        <table>
          <tbody>
            {engines.data.map((e) => (
              <tr key={e.name}>
                <td>{ENGINE_LABELS[e.name] ?? e.name}</td>
                <td>
                  <span className={STATUS_CLASS[e.status] ?? "pill"}>{e.status}</span>
                </td>
                <td>
                  {e.message}
                  {e.signatures_at && <span className="muted"> · signatures {age(e.signatures_at)}</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

const SEVERITY_CLASS: Record<Severity, string> = {
  malicious: "pill bad",
  suspicious: "pill warn",
  info: "pill muted-pill",
};

/** What the engines found, most severe first. Verdicts and triage come in M4. */
export function DetectionsPanel() {
  const detections = useQuery({ queryKey: ["detections"], queryFn: api.detections, refetchInterval: 60_000 });
  if (!detections.data?.length) return null;
  return (
    <section className="card">
      <h2>Detections</h2>
      <table>
        <thead>
          <tr>
            <th>Severity</th>
            <th>File</th>
            <th>Engine</th>
            <th>What</th>
            <th>Seen</th>
          </tr>
        </thead>
        <tbody>
          {detections.data.map((d) => (
            <tr key={d.id}>
              <td>
                <span className={SEVERITY_CLASS[d.severity]}>{d.severity}</span>
              </td>
              <td className="mono wrap">
                {d.path}
                {d.member && <span className="muted"> → {d.member}</span>}
              </td>
              <td>{ENGINE_LABELS[d.engine] ?? d.engine}</td>
              <td title={d.name}>{d.description ?? d.name}</td>
              <td>{new Date(d.last_seen).toLocaleString()}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
