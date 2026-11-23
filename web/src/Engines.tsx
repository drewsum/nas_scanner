import { useQuery } from "@tanstack/react-query";
import { api } from "./api";
import { ago } from "./util";

export const ENGINE_LABELS: Record<string, string> = {
  clamav: "ClamAV",
  yara: "YARA",
  heuristics: "Heuristics",
  documents: "Documents",
  printing: "3D print files",
  "malwarebazaar-feed": "MalwareBazaar feed",
  "threatfox-feed": "ThreatFox feed",
  "virusshare-feed": "VirusShare feed",
  circl: "CIRCL",
  cymru: "Team Cymru",
  malwarebazaar: "MalwareBazaar",
  yaraify: "YARAify",
  virustotal: "VirusTotal",
  "hybrid-analysis": "Hybrid Analysis",
  metadefender: "MetaDefender",
  otx: "AlienVault OTX",
  opentip: "Kaspersky OpenTIP",
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
  idle: "pill muted-pill",
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

/** Hash feeds and live lookup providers: on or off, freshness, and quota use. */
export function IntelPanel() {
  const intel = useQuery({ queryKey: ["intel"], queryFn: api.intel, refetchInterval: 60_000 });
  if (!intel.data?.length) return null;
  const on = intel.data.filter((p) => p.enabled);
  const off = intel.data.filter((p) => !p.enabled);
  return (
    <section className="card">
      <h2>Threat intel</h2>
      <table>
        <thead>
          <tr>
            <th>Source</th>
            <th>Status</th>
            <th>Used today</th>
            <th>Last success</th>
            <th>Details</th>
          </tr>
        </thead>
        <tbody>
          {on.map((p) => (
            <tr key={p.name}>
              <td title={p.title}>{ENGINE_LABELS[p.name] ?? p.title}</td>
              <td>
                <span className={STATUS_CLASS[p.status] ?? "pill"}>{p.status}</span>
              </td>
              <td>
                {p.kind === "lookup" && p.daily_budget
                  ? `${p.requests_today.toLocaleString()} / ${p.daily_budget.toLocaleString()}`
                  : p.kind === "feed"
                    ? `${p.entries.toLocaleString()} hashes`
                    : ""}
              </td>
              <td>{ago(p.last_success)}</td>
              <td>
                {p.message}
                {!!p.details?.pending && (
                  <span className="muted"> · {p.details.pending.toLocaleString()} waiting</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {off.length > 0 && (
        <details className="muted">
          <summary>{off.length} more sources are off</summary>
          <ul>
            {off.map((p) => (
              <li key={p.name}>
                {ENGINE_LABELS[p.name] ?? p.title}: {p.message}
              </li>
            ))}
          </ul>
        </details>
      )}
    </section>
  );
}
