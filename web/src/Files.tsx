import { useQuery } from "@tanstack/react-query";
import { useEffect, useState, type ReactNode } from "react";
import { api } from "./api";
import { ENGINE_LABELS } from "./Engines";
import { formatBytes, HashLinks, setQuery, VERDICT_CLASS, when, type Route } from "./util";

const label = (engine: string) => ENGINE_LABELS[engine] ?? engine;

/** Wait until typing pauses before searching. */
function useDebounced<T>(value: T, ms = 300): T {
  const [settled, setSettled] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setSettled(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return settled;
}

/** Find any file by part of its path, or every copy of some content by its hash. */
export function FilesPage({ route }: { route: Route }) {
  const [q, setQ] = useState(route.query.get("q") ?? "");
  const [removed, setRemoved] = useState(route.query.get("removed") === "1");
  const term = useDebounced(q.trim());
  const search = useQuery({
    queryKey: ["files", term, removed],
    queryFn: () => api.searchFiles(term, removed),
    enabled: term.length >= 2,
    placeholderData: (previous) => previous,
  });
  useEffect(() => setQuery("/files", { q: term, removed: removed ? "1" : "" }), [term, removed]);
  const data = term.length >= 2 ? search.data : undefined;

  return (
    <div className="page">
      <section className="card">
        <h2>Files</h2>
        <div className="toolbar">
          <label className="visually-hidden" htmlFor="file-q">
            Path or hash
          </label>
          <input
            id="file-q"
            className="search"
            type="search"
            autoFocus
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Part of a path, or an MD5, SHA-1 or SHA-256"
          />
          <label className="check">
            <input type="checkbox" checked={removed} onChange={(e) => setRemoved(e.target.checked)} />
            Include removed
          </label>
        </div>
        {search.error && <p className="error">{search.error.message}</p>}
        {data?.files.length === 0 && <p className="muted">No files match.</p>}
        {data && data.files.length > 0 && (
          <>
            <p className="muted small">
              {data.match === "hash" ? "Every copy of this content, removed ones too." : null}
              {data.truncated && ` The first ${data.files.length}; narrow the search for more.`}
            </p>
            <table className="stack">
              <thead>
                <tr>
                  <th>Path</th>
                  <th>Size</th>
                  <th>Type</th>
                  <th>Last read</th>
                  <th>Verdict</th>
                </tr>
              </thead>
              <tbody>
                {data.files.map((f) => (
                  <tr key={f.id}>
                    <td className="mono wrap">
                      <a href={`#/files/${f.id}`}>{f.path}</a>
                      {f.status !== "active" && <span className="muted"> ({f.status})</span>}
                    </td>
                    <td data-label="Size">{formatBytes(f.size)}</td>
                    <td data-label="Type" className="muted">
                      {f.mime}
                    </td>
                    <td data-label="Read">{when(f.last_scanned)}</td>
                    <td>
                      {f.verdict && f.finding_status !== "resolved" && (
                        <span className={VERDICT_CLASS[f.verdict]}>{f.verdict}</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}
        {term.length < 2 && (
          <p className="muted small">
            Search every file the scanner has seen. A whole hash finds every copy of that content, under any name.
          </p>
        )}
      </section>
    </div>
  );
}

const LOOKUP_CLASS: Record<string, string> = {
  malicious: "pill bad",
  suspicious: "pill warn",
  known_good: "pill ok",
  clean: "pill ok",
};

/** One file: what it is, every engine's and provider's opinion, and its history. */
export function FilePage({ id }: { id: number }) {
  const file = useQuery({ queryKey: ["file", id], queryFn: () => api.file(id) });
  const f = file.data;
  if (file.error) return <p className="error">{file.error.message}</p>;
  if (!f) return null;
  const facts: [string, ReactNode][] = [
    ["Path", <span className="mono">{f.path}</span>],
    ["Status", f.status === "error" ? `unreadable: ${f.error}` : f.status],
    ["Size", `${formatBytes(f.size)} (${f.size.toLocaleString()} bytes)`],
    ["Modified", when(f.mtime)],
    ["Type", [f.mime, f.magic].filter(Boolean).join(" — ") || "unknown"],
    ["Read", f.scan_mode === "partial" ? "start and end only (large media)" : f.scan_mode ? "whole file" : "not yet"],
    ["SHA-256", <span className="mono">{f.sha256 ?? "—"}</span>],
    ["SHA-1", <span className="mono">{f.sha1 ?? "—"}</span>],
    ["MD5", <span className="mono">{f.md5 ?? "—"}</span>],
  ];

  return (
    <div className="page">
      <a href="#/files" className="back">
        ← Files
      </a>
      <div className="detail-head">
        <h1 className="mono wrap-anywhere">{f.path.split("/").pop()}</h1>
        {f.finding && (
          <a href={`#/findings/${f.finding.id}`}>
            <span className={VERDICT_CLASS[f.finding.verdict]}>{f.finding.verdict}</span>{" "}
            <span className="muted">finding ({f.finding.status})</span>
          </a>
        )}
      </div>
      <section className="card">
        <dl className="facts">
          {facts.map(([k, v]) => (
            <div key={k}>
              <dt>{k}</dt>
              <dd>{v}</dd>
            </div>
          ))}
          {f.sha256 && (
            <>
              <div>
                <dt>Look up</dt>
                <dd>
                  <HashLinks sha256={f.sha256} />
                </dd>
              </div>
              <div>
                <dt>Copies</dt>
                <dd>
                  <a href={`#/files?q=${f.sha256}`}>Find every copy</a>
                </dd>
              </div>
            </>
          )}
        </dl>
      </section>

      <section className="card">
        <h2>Detections</h2>
        {f.detections.length === 0 && f.feeds.length === 0 ? (
          <p className="muted">None. No engine or feed flags this file.</p>
        ) : (
          <table className="stack">
            <thead>
              <tr>
                <th>Engine</th>
                <th>Severity</th>
                <th>What</th>
                <th>Since</th>
              </tr>
            </thead>
            <tbody>
              {f.detections.map((d, i) => (
                <tr key={i}>
                  <td>{label(d.engine)}</td>
                  <td>{d.severity}</td>
                  <td className="wrap">
                    <span className="mono">{d.name}</span>
                    {d.description && d.description !== d.name && <> — {d.description}</>}
                    {d.member && <span className="muted mono"> in {d.member}</span>}
                    {d.link && (
                      <>
                        {" "}
                        <a href={d.link} target="_blank" rel="noreferrer noopener">
                          report
                        </a>
                      </>
                    )}
                  </td>
                  <td data-label="Since" className="muted">
                    {when(d.first_seen)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section className="card">
        <h2>Threat intel</h2>
        {f.feeds.length === 0 && f.lookups.length === 0 && (
          <p className="muted">
            {f.sha256
              ? "No feed lists it, and no provider has been asked yet (live lookups go to likely-risky files first)."
              : "Not hashed, so not looked up."}
          </p>
        )}
        {(f.feeds.length > 0 || f.lookups.length > 0) && (
          <table className="stack">
            <tbody>
              {f.feeds.map((x) => (
                <tr key={`feed-${x.feed}`}>
                  <td>{label(x.feed)}</td>
                  <td>
                    <span className="pill bad">listed</span>
                  </td>
                  <td>
                    {x.name ?? ""} <span className="muted">({x.hash_type} match)</span>
                  </td>
                  <td />
                </tr>
              ))}
              {f.lookups.map((x) => (
                <tr key={`lookup-${x.provider}`}>
                  <td>{label(x.provider)}</td>
                  <td>
                    <span className={LOOKUP_CLASS[x.verdict] ?? "pill muted-pill"}>{x.verdict.replace("_", " ")}</span>
                  </td>
                  <td>{x.name}</td>
                  <td data-label="Asked" className="muted">
                    {when(x.looked_up_at)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section className="card">
        <h2>History</h2>
        <ul className="timeline">
          {f.history.map((e, i) => (
            <li key={i}>
              <time dateTime={e.at}>{when(e.at)}</time>
              {e.what.startsWith("Last seen (scan ") && f.last_seen_run_id ? (
                <>
                  Last seen in <a href={`#/scans/${f.last_seen_run_id}`}>scan {f.last_seen_run_id}</a>
                </>
              ) : (
                e.what
              )}
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}
