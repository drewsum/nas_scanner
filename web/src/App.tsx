import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { api, UNAUTHORIZED_EVENT } from "./api";
import { Login } from "./Login";
import { EnginesPanel, IntelPanel } from "./Engines";
import { AllowlistPanel, FindingsPanel } from "./Findings";
import { RunsPanel } from "./Runs";

// Pages register here as milestones land (M5: dashboard, runs, findings, files, providers).
const NAV: [string, string][] = [["#/", "Dashboard"]];

function useHash(): string {
  const [hash, setHash] = useState(window.location.hash);
  useEffect(() => {
    const onChange = () => {
      setHash(window.location.hash);
      window.scrollTo(0, 0);
    };
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  return hash;
}

function Dashboard() {
  return (
    <div className="stack">
      <FindingsPanel />
      <RunsPanel />
      <EnginesPanel />
      <IntelPanel />
      <AllowlistPanel />
    </div>
  );
}

export function App() {
  const client = useQueryClient();
  const health = useQuery({ queryKey: ["health"], queryFn: api.health });
  const session = useQuery({ queryKey: ["session"], queryFn: api.session });
  const logout = useMutation({
    mutationFn: api.logout,
    onSuccess: (s) => {
      client.removeQueries({ predicate: (q) => q.queryKey[0] !== "session" });
      client.setQueryData(["session"], s);
    },
  });
  const hash = useHash() || "#/";
  const signedIn = !!session.data && (!session.data.auth_enabled || session.data.authenticated);

  // Any 401 (an expired session, or a password change) means: show the login page.
  useEffect(() => {
    const onUnauthorized = () => void client.invalidateQueries({ queryKey: ["session"] });
    window.addEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
  }, [client]);

  const s = session.data;
  let page;
  if (!s) page = session.error ? <p className="error">API unreachable.</p> : null;
  else if (s.auth_enabled && !s.authenticated) page = <Login />;
  else page = <Dashboard />;

  return (
    <main>
      <header className="app-head">
        <a href="#/" className="brand">
          NAS Scanner
        </a>
        {signedIn && (
          <nav className="nav">
            {NAV.map(([href, label]) => (
              <a key={href} href={href} aria-current={hash === href ? "page" : undefined}>
                {label}
              </a>
            ))}
          </nav>
        )}
        <span
          className={health.data?.status === "ok" ? "pill ok" : "pill bad"}
          title={health.data ? `commit ${health.data.commit}` : undefined}
        >
          {health.isPending ? "checking…" : health.data ? `API ${health.data.version}` : "API down"}
        </span>
        {s?.auth_enabled && s.authenticated && (
          <button type="button" className="plain logout" onClick={() => logout.mutate()}>
            Log out
          </button>
        )}
      </header>
      {s && !s.auth_enabled && (
        <p className="warning">
          No admin password is set, so anyone on your network can view this. Set
          NASSCAN_ADMIN_PASSWORD to require a login.
        </p>
      )}
      {page}
    </main>
  );
}
