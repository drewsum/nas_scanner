import { useQuery } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { api } from "./api";
import { OpenFindings } from "./Findings";
import { Masthead } from "./Masthead";
import { isActive, RUN_STATUS_CLASS, RunsTable, ScanControls, useRuns } from "./Runs";
import { ago, formatBytes, when } from "./util";

function Tile({ label, value, sub, href, tone }: { label: string; value: ReactNode; sub?: ReactNode; href?: string; tone?: "bad" | "warn" | "ok" }) {
  const body = (
    <>
      <span className="tile-label">{label}</span>
      <span className={`tile-value${tone ? ` ${tone}` : ""}`}>{value}</span>
      {sub && <span className="tile-sub">{sub}</span>}
    </>
  );
  return href ? (
    <a className="tile" href={href}>
      {body}
    </a>
  ) : (
    <div className="tile">{body}</div>
  );
}

function ThreatsTile() {
  const summary = useQuery({ queryKey: ["finding-summary"], queryFn: api.findingSummary });
  const open = summary.data?.counts.open ?? {};
  const acknowledged = summary.data?.counts.acknowledged ?? {};
  const total = (open.malicious ?? 0) + (open.suspicious ?? 0);
  const acked = (acknowledged.malicious ?? 0) + (acknowledged.suspicious ?? 0);
  if (!summary.data) return <Tile label="Open threats" value="…" />;
  return (
    <Tile
      label="Open threats"
      value={total}
      tone={open.malicious ? "bad" : total ? "warn" : "ok"}
      href="#/findings"
      sub={
        total
          ? `${open.malicious ?? 0} malicious, ${open.suspicious ?? 0} suspicious`
          : acked
            ? `${acked} acknowledged`
            : "All clear"
      }
    />
  );
}

function InventoryTile() {
  const stats = useQuery({ queryKey: ["file-stats"], queryFn: api.fileStats, refetchInterval: 60_000 });
  const s = stats.data;
  if (!s) return <Tile label="Files on the NAS" value="…" />;
  const notes = [formatBytes(s.bytes)];
  if (s.read_partly) notes.push(`${s.read_partly.toLocaleString()} large media read in part`);
  if (s.unreadable) notes.push(`${s.unreadable.toLocaleString()} unreadable`);
  return <Tile label="Files on the NAS" value={s.files.toLocaleString()} sub={notes.join(" · ")} href="#/files" />;
}

function LastScanTile() {
  const runs = useRuns(20);
  const active = runs.data?.find(isActive);
  const last = runs.data?.find((r) => !isActive(r));
  if (active)
    return (
      <Tile
        label="Scanning now"
        value={active.files_seen.toLocaleString()}
        sub={`files so far, ${formatBytes(active.bytes_hashed)} read (${active.kind})`}
        href={`#/scans/${active.id}`}
      />
    );
  if (!last) return <Tile label="Last scan" value="None yet" sub="The first scheduled one runs tonight" />;
  return (
    <Tile
      label="Last scan"
      value={<span className={RUN_STATUS_CLASS[last.status] ?? "pill"}>{last.status}</span>}
      tone={last.status === "failed" ? "bad" : undefined}
      sub={`${last.kind}, ${ago(last.finished_at ?? last.requested_at)}: ${last.files_seen.toLocaleString()} files, ${last.files_flagged} flagged, ${last.errors} errors`}
      href={`#/scans/${last.id}`}
    />
  );
}

/** How current the signatures and feeds are, and whether anything is broken. */
function FreshnessTile() {
  const engines = useQuery({ queryKey: ["engines"], queryFn: api.engines, refetchInterval: 60_000 });
  const intel = useQuery({ queryKey: ["intel"], queryFn: api.intel, refetchInterval: 60_000 });
  if (!engines.data || !intel.data) return <Tile label="Signatures" value="…" />;
  const sigs = engines.data.filter((e) => e.signatures_at).map((e) => new Date(e.signatures_at!).getTime());
  const oldest = sigs.length ? new Date(Math.min(...sigs)).toISOString() : null;
  const enabled = intel.data.filter((p) => p.enabled);
  const broken = [...engines.data.filter((e) => e.status === "error"), ...enabled.filter((p) => p.status === "error")];
  const feeds = enabled.filter((p) => p.kind === "feed");
  return (
    <Tile
      label="Signatures"
      value={oldest ? ago(oldest).replace(" ago", " old") : "unknown"}
      tone={broken.length ? "bad" : undefined}
      sub={
        broken.length
          ? `${broken.length} with errors: ${broken.map((b) => b.name).join(", ")}`
          : `oldest engine's signatures; ${feeds.length} feeds and ${enabled.length - feeds.length} lookups on`
      }
      href="#/status"
    />
  );
}

export function Dashboard() {
  const stats = useQuery({ queryKey: ["file-stats"], queryFn: api.fileStats, refetchInterval: 60_000 });
  return (
    <div className="page">
      <Masthead />
      <div className="tiles">
        <ThreatsTile />
        <InventoryTile />
        <LastScanTile />
        <FreshnessTile />
      </div>
      <OpenFindings />
      <ScanControls />
      <RunsTable limit={5} title="Recent scans" />
      {stats.data?.last_scanned && (
        <p className="muted small">Last file read {when(stats.data.last_scanned)}.</p>
      )}
    </div>
  );
}
