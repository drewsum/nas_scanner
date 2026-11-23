import { useEffect, useState } from "react";

export function formatBytes(n: number): string {
  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i++;
  }
  return `${n.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

export function when(iso: string | null | undefined): string {
  return iso ? new Date(iso).toLocaleString() : "";
}

export function ago(iso: string | null): string {
  if (!iso) return "never";
  const minutes = (Date.now() - new Date(iso).getTime()) / 60_000;
  if (minutes < 2) return "just now";
  if (minutes < 120) return `${Math.round(minutes)} min ago`;
  if (minutes < 2880) return `${Math.round(minutes / 60)} h ago`;
  return `${Math.round(minutes / 1440)} days ago`;
}

/** The location hash as a path and its query: "#/files?q=x" -> ["/files", {q: "x"}]. */
export interface Route {
  path: string;
  parts: string[];
  query: URLSearchParams;
}

function parse(hash: string): Route {
  const raw = hash.replace(/^#/, "") || "/";
  const [path, qs = ""] = raw.split("?", 2);
  return { path, parts: path.split("/").filter(Boolean), query: new URLSearchParams(qs) };
}

export function useRoute(): Route {
  const [hash, setHash] = useState(window.location.hash);
  useEffect(() => {
    const onChange = () => {
      setHash(window.location.hash);
      window.scrollTo(0, 0);
    };
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  return parse(hash);
}

/** Update the hash's query without adding a history entry per keystroke. */
export function setQuery(path: string, params: Record<string, string>) {
  const qs = new URLSearchParams(Object.entries(params).filter(([, v]) => v)).toString();
  window.history.replaceState(null, "", `#${path}${qs ? `?${qs}` : ""}`);
}

/** Public pages about a SHA-256. Opening one sends only the hash, and only when clicked. */
export const HASH_LINKS: [string, (sha: string) => string][] = [
  ["VirusTotal", (h) => `https://www.virustotal.com/gui/file/${h}`],
  ["MalwareBazaar", (h) => `https://bazaar.abuse.ch/sample/${h}/`],
  ["Hybrid Analysis", (h) => `https://www.hybrid-analysis.com/sample/${h}`],
  ["MetaDefender", (h) => `https://metadefender.com/results/hash/${h}`],
  ["OTX", (h) => `https://otx.alienvault.com/indicator/file/${h}`],
  ["Kaspersky OpenTIP", (h) => `https://opentip.kaspersky.com/${h}/results`],
];

export function HashLinks({ sha256 }: { sha256: string }) {
  return (
    <span className="links">
      {HASH_LINKS.map(([name, url]) => (
        <a key={name} href={url(sha256)} target="_blank" rel="noreferrer noopener">
          {name}
        </a>
      ))}
    </span>
  );
}

export const VERDICT_CLASS: Record<string, string> = {
  malicious: "pill bad",
  suspicious: "pill warn",
};
