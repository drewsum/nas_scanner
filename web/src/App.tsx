import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect } from "react";
import { api, UNAUTHORIZED_EVENT } from "./api";
import { Login } from "./Login";
import { Dashboard } from "./Dashboard";
import { EnginesPanel, IntelPanel } from "./Engines";
import { FilePage, FilesPage } from "./Files";
import { AllowlistPanel, FindingPage, FindingsPage } from "./Findings";
import { ReportsPage } from "./Reports";
import { RunPage, RunsPage } from "./Runs";
import { useRoute, type Route } from "./util";

const NAV: [string, string][] = [
  ["", "Dashboard"],
  ["findings", "Findings"],
  ["scans", "Scans"],
  ["files", "Files"],
  ["reports", "Reports"],
  ["status", "Status"],
  ["allowlist", "Allowlist"],
];

function Page({ route }: { route: Route }) {
  const [section, rawId] = route.parts;
  const id = Number(rawId);
  const withId = rawId !== undefined && Number.isInteger(id) && id > 0;
  switch (section ?? "") {
    case "":
      return <Dashboard />;
    case "findings":
      return withId ? <FindingPage key={id} id={id} /> : <FindingsPage route={route} />;
    case "scans":
      return withId ? <RunPage key={id} id={id} /> : <RunsPage />;
    case "files":
      return withId ? <FilePage key={id} id={id} /> : <FilesPage route={route} />;
    case "reports":
      return <ReportsPage />;
    case "status":
      return (
        <div className="page">
          <EnginesPanel />
          <IntelPanel />
        </div>
      );
    case "allowlist":
      return (
        <div className="page">
          <AllowlistPanel />
        </div>
      );
    default:
      return (
        <p className="muted">
          No such page. <a href="#/">Dashboard</a>
        </p>
      );
  }
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
  const route = useRoute();
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
  else page = <Page route={route} />;

  return (
    <main>
      <header className="app-head">
        <a href="#/" className="brand">
          NAS Scanner
        </a>
        {signedIn && (
          <nav className="nav">
            {NAV.map(([section, label]) => (
              <a
                key={section}
                href={`#/${section}`}
                aria-current={(route.parts[0] ?? "") === section ? "page" : undefined}
              >
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
