import { Icon, type IconName } from "../icons";

export type ViewId =
  | "overview"
  | "findings"
  | "incidents"
  | "assets"
  | "network"
  | "application"
  | "infrastructure"
  | "identity"
  | "monitoring"
  | "investigations"
  | "governance"
  | "supply-chain"
  | "evidence"
  | "validation"
  | "responses"
  | "report";

export const NAV: { id: ViewId; title: string; icon: IconName }[] = [
  { id: "overview", title: "Overview", icon: "overview" },
  { id: "findings", title: "Findings", icon: "findings" },
  { id: "incidents", title: "Incidents", icon: "incidents" },
  { id: "assets", title: "Assets", icon: "assets" },
  { id: "network", title: "Network", icon: "network" },
  { id: "application", title: "Application", icon: "application" },
  { id: "infrastructure", title: "Infrastructure", icon: "infrastructure" },
  { id: "identity", title: "Identity", icon: "identity" },
  { id: "monitoring", title: "Monitoring", icon: "monitoring" },
  { id: "investigations", title: "Investigations", icon: "investigations" },
  { id: "governance", title: "Governance", icon: "governance" },
  { id: "supply-chain", title: "Supply Chain", icon: "supply-chain" },
  { id: "evidence", title: "Evidence", icon: "evidence" },
  { id: "validation", title: "Validation", icon: "validation" },
  { id: "responses", title: "Responses", icon: "responses" },
  { id: "report", title: "Report", icon: "report" },
];

export function Shell({
  view,
  onNavigate,
  collapsed,
  onToggleNav,
  onOpenPalette,
  onToggleTheme,
  theme,
  titles,
  children,
}: {
  view: ViewId;
  onNavigate: (v: ViewId) => void;
  collapsed: boolean;
  onToggleNav: () => void;
  onOpenPalette: () => void;
  onToggleTheme: () => void;
  theme: "light" | "dark";
  titles: Record<ViewId, string>;
  children: React.ReactNode;
}) {
  return (
    <div className="shell">
      <aside
        className={`sidebar${collapsed ? " collapsed" : ""}`}
        aria-label="Primary"
      >
        <div className="brand">
          <span className="brand-mark" aria-hidden="true">
            <Icon name="shield" />
          </span>
          <span>
            <span className="brand-name">Blueveil</span>
            <br />
            <span className="brand-sub">Security Workstation</span>
          </span>
        </div>
        <nav className="nav" aria-label="Views">
          <div className="nav-group-label">Workstation</div>
          {NAV.map((item) => (
            <button
              key={item.id}
              className={`nav-item${view === item.id ? " active" : ""}`}
              aria-current={view === item.id ? "page" : undefined}
              onClick={() => onNavigate(item.id)}
            >
              <Icon name={item.icon} />
              {item.title}
            </button>
          ))}
        </nav>
        <div className="sidebar-foot">Read-only · loopback API</div>
      </aside>
      <div className="main">
        <header className="topbar">
          <button
            className="icon-btn"
            onClick={onToggleNav}
            aria-label={collapsed ? "Show navigation" : "Hide navigation"}
          >
            <Icon name="panel" />
          </button>
          <div className="topbar-crumbs">
            Blueveil / <strong>{titles[view]}</strong>
          </div>
          <div className="topbar-spacer" />
          <button
            className="search-pill"
            onClick={onOpenPalette}
            aria-label="Search (Control K)"
          >
            <Icon name="search" />
            <span>Search…</span>
            <span className="kbd">⌃K</span>
          </button>
          <button
            className="icon-btn"
            onClick={onToggleTheme}
            aria-label={
              theme === "light" ? "Switch to dark mode" : "Switch to light mode"
            }
          >
            <Icon name={theme === "light" ? "moon" : "sun"} />
          </button>
        </header>
        <main className="workspace">{children}</main>
      </div>
    </div>
  );
}
