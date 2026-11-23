export interface Health {
  status: string;
  version: string;
  commit: string;
  database: boolean;
}

export interface Session {
  auth_enabled: boolean;
  authenticated: boolean;
}

export type RunKind = "incremental" | "full" | "path";
export type RunStatus = "queued" | "running" | "completed" | "failed" | "cancelled";

export interface ScanRun {
  id: number;
  kind: RunKind;
  root: string;
  trigger: "schedule" | "manual";
  status: RunStatus;
  requested_at: string;
  started_at: string | null;
  finished_at: string | null;
  updated_at: string | null;
  resumed: number;
  files_seen: number;
  files_new: number;
  files_changed: number;
  files_unchanged: number;
  files_removed: number;
  files_hashed: number;
  bytes_seen: number;
  bytes_hashed: number;
  errors: number;
  current_path: string | null;
  last_error: string | null;
  message: string | null;
}

/** Fired when the API answers 401, so the app can show the login page. */
export const UNAUTHORIZED_EVENT = "nasscan:unauthorized";

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, {
    method,
    headers: body === undefined ? undefined : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (res.status === 401 && !path.startsWith("/api/auth/")) {
    window.dispatchEvent(new Event(UNAUTHORIZED_EVENT));
  }
  if (!res.ok) {
    const detail = await res
      .json()
      .then((j: { detail?: unknown }) => (typeof j.detail === "string" ? j.detail : ""))
      .catch(() => "");
    throw new Error(detail || `${method} ${path}: ${res.status}`);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

const get = <T>(path: string) => request<T>("GET", path);

export const api = {
  health: () => get<Health>("/api/health"),
  session: () => get<Session>("/api/auth/session"),
  login: (password: string) => request<Session>("POST", "/api/auth/login", { password }),
  logout: () => request<Session>("POST", "/api/auth/logout"),
  runs: () => get<ScanRun[]>("/api/runs?limit=20"),
  startRun: (kind: RunKind, path = "") => request<ScanRun>("POST", "/api/runs", { kind, path }),
  cancelRun: (id: number) => request<ScanRun>("POST", `/api/runs/${id}/cancel`),
};
