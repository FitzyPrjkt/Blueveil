import { useCallback, useEffect, useMemo, useState } from "react";
import { hasApiKey, isAuthRequired, onAuthRequired, setApiKey } from "./api";
import { parseAlert, parseAsset, parseIncident } from "./contracts";
import { CommandPalette, type PaletteItem } from "./components/CommandPalette";
import { NAV, Shell, type ViewId } from "./components/Shell";
import { useTheme } from "./theme";
import { Application } from "./views/Application";
import { Assets } from "./views/Assets";
import { EvidenceView } from "./views/Evidence";
import { Findings } from "./views/Findings";
import { Incidents } from "./views/Incidents";
import { Identity } from "./views/Identity";
import { Infrastructure } from "./views/Infrastructure";
import { Governance } from "./views/Governance";
import { SupplyChain } from "./views/SupplyChain";
import { Investigations } from "./views/Investigations";
import { Monitoring } from "./views/Monitoring";
import { Network } from "./views/Network";
import { Overview } from "./views/Overview";
import { Responses } from "./views/Responses";
import { Validation } from "./views/Validation";
import { ReportView } from "./views/ReportView";
import { useApiList } from "./views/hooks";

const TITLES: Record<ViewId, string> = {
  overview: "Overview",
  findings: "Findings",
  incidents: "Incidents",
  assets: "Assets",
  network: "Network",
  application: "Application",
  infrastructure: "Infrastructure",
  identity: "Identity",
  monitoring: "Monitoring",
  investigations: "Investigations",
  governance: "Governance",
  "supply-chain": "Supply Chain",
  evidence: "Evidence",
  validation: "Validation",
  responses: "Responses",
  report: "Report",
};

function viewFromHash(): ViewId {
  const h = window.location.hash.replace("#/", "");
  const v = h.split("?")[0] ?? h;
  return (NAV.some((n) => n.id === v) ? v : "overview") as ViewId;
}

// Optional ?k=v after the view id, e.g. #/findings?severity=SEVERITY_CRITICAL.
// Views consume these as initial filter values only (no two-way sync).
function hashQuery(): URLSearchParams {
  const h = window.location.hash.replace("#/", "");
  const qi = h.indexOf("?");
  return new URLSearchParams(qi === -1 ? "" : h.slice(qi + 1));
}

export function App() {
  const [view, setView] = useState<ViewId>(viewFromHash);
  const [query, setQuery] = useState<URLSearchParams>(hashQuery);
  const [collapsed, setCollapsed] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [focusAlertId, setFocusAlertId] = useState<string | null>(null);
  const { theme, toggle } = useTheme();
  const alerts = useApiList("/api/v1/alerts", parseAlert);
  const assets = useApiList("/api/v1/assets", parseAsset);
  const incidents = useApiList("/api/v1/incidents", parseIncident);

  const navigate = useCallback((v: ViewId) => {
    setView(v);
    setFocusAlertId(null);
    setQuery(new URLSearchParams());
    window.location.hash = `#/${v}`;
  }, []);

  useEffect(() => {
    const onHash = () => {
      setView(viewFromHash());
      setQuery(hashQuery());
      setFocusAlertId(null);
    };
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen((o) => !o);
      } else if (
        e.key === "/" &&
        !(e.target instanceof HTMLInputElement) &&
        !(e.target instanceof HTMLSelectElement)
      ) {
        const input = document.querySelector<HTMLElement>(
          '[role="search"] input',
        );
        if (input) {
          e.preventDefault();
          input.focus();
        }
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, []);

  const paletteItems = useMemo<PaletteItem[]>(() => {
    const items: PaletteItem[] = NAV.map((n) => ({
      id: `nav-${n.id}`,
      group: "Views",
      label: `Go to ${n.title}`,
      run: () => navigate(n.id),
    }));
    if (alerts.kind === "ready") {
      for (const a of alerts.data.slice(0, 20)) {
        items.push({
          id: `alert-${a.id}`,
          group: "Findings",
          label: a.title,
          hint: a.severity.replace("SEVERITY_", ""),
          run: () => navigate("findings"),
        });
      }
    }
    if (incidents.kind === "ready") {
      for (const i of incidents.data.slice(0, 20)) {
        const id = i.id;
        items.push({
          id: `incident-${id}`,
          group: "Incidents",
          label: i.title,
          hint: i.status.replace("INCIDENT_STATUS_", ""),
          run: () => navigate("incidents"),
        });
      }
    }
    if (assets.kind === "ready") {
      for (const a of assets.data.slice(0, 20)) {
        items.push({
          id: `asset-${a.id}`,
          group: "Assets",
          label: a.name,
          hint: a.type.replace("ASSET_TYPE_", ""),
          run: () => navigate("assets"),
        });
      }
    }
    return items;
  }, [alerts, incidents, assets, navigate]);

  // Production API authentication: when any request reports 401, show
  // the unlock panel. The key lives in session storage only (never
  // localStorage, never logged) and is sent as a Bearer credential.
  const [locked, setLocked] = useState(isAuthRequired);
  const [keyInput, setKeyInput] = useState("");
  useEffect(() => onAuthRequired(setLocked), []);
  const unlock = useCallback(() => {
    setApiKey(keyInput);
    setKeyInput("");
    window.location.reload();
  }, [keyInput]);
  const lock = useCallback(() => {
    setApiKey("");
    window.location.reload();
  }, []);

  return (
    <Shell
      view={view}
      onNavigate={navigate}
      collapsed={collapsed}
      onToggleNav={() => setCollapsed((c) => !c)}
      onOpenPalette={() => setPaletteOpen(true)}
      onToggleTheme={toggle}
      theme={theme}
      titles={TITLES}
    >
      {locked && (
        <div className="panel" role="alert">
          <h2>Authentication required</h2>
          <p className="muted">
            This workstation is protected. Enter an API key to continue;
            {hasApiKey()
              ? " the stored key was rejected."
              : " no key is stored for this session."}
          </p>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              unlock();
            }}
          >
            <input
              type="password"
              aria-label="API key"
              value={keyInput}
              onChange={(e) => setKeyInput(e.target.value)}
              placeholder="API key"
              autoComplete="off"
            />{" "}
            <button type="submit">Unlock</button>{" "}
            <button type="button" onClick={lock}>
              Forget key
            </button>
          </form>
        </div>
      )}
      {view === "overview" && <Overview />}
      {view === "findings" && (
        <Findings
          initialSeverity={query.get("severity") ?? undefined}
          initialStatus={query.get("status") ?? undefined}
          initialSort={query.get("sort") ?? undefined}
          onOpenIncident={(alertId) => {
            setFocusAlertId(alertId);
            navigate("incidents");
            // Re-set after navigate clears it.
            setTimeout(() => setFocusAlertId(alertId), 0);
          }}
        />
      )}
      {view === "incidents" && <Incidents focusAlertId={focusAlertId} />}
      {view === "assets" && (
        <Assets initialStatus={query.get("status") ?? undefined} />
      )}
      {view === "network" && <Network />}
      {view === "application" && <Application />}
      {view === "infrastructure" && <Infrastructure />}
      {view === "identity" && <Identity />}
      {view === "monitoring" && <Monitoring />}
      {view === "investigations" && <Investigations />}
      {view === "governance" && <Governance />}
      {view === "supply-chain" && <SupplyChain />}
      {view === "evidence" && <EvidenceView />}
      {view === "validation" && <Validation />}
      {view === "responses" && <Responses />}
      {view === "report" && <ReportView />}
      <CommandPalette
        open={paletteOpen}
        onClose={() => setPaletteOpen(false)}
        items={paletteItems}
      />
    </Shell>
  );
}
