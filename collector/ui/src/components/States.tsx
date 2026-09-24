import type { IconName } from "../icons";
import { Icon } from "../icons";

// Structural states (F, I): skeletons mirror eventual content; empty states
// carry honest copy; backend errors never render as empty tables.
export function StatSkeleton() {
  return (
    <div className="stat-grid" aria-label="Loading statistics" role="status">
      {[0, 1, 2, 3, 4, 5].map((i) => (
        <div key={i} className="stat-card">
          <div
            className="skeleton"
            style={{ height: 12, width: 90, marginBottom: 8 }}
          />
          <div className="skeleton" style={{ height: 30, width: 70 }} />
        </div>
      ))}
    </div>
  );
}

export function TableSkeleton({ rows = 5 }: { rows?: number }) {
  return (
    <div role="status" aria-label="Loading table">
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} className="skeleton skel-row" />
      ))}
    </div>
  );
}

export function HeadingSkeleton() {
  return (
    <div role="status" aria-label="Loading">
      <div className="skeleton skel-title" />
      <div className="skeleton skel-meta" />
    </div>
  );
}

export function EmptyState({
  icon,
  title,
  description,
  action,
  secondary,
}: {
  icon: IconName;
  title: string;
  description: string;
  action?: { label: string; onClick: () => void };
  secondary?: string;
}) {
  return (
    <div className="empty">
      <span className="empty-icon" aria-hidden="true">
        <Icon name={icon} />
      </span>
      <h3 className="empty-title">{title}</h3>
      <p className="empty-desc">{description}</p>
      {action && (
        <button type="button" onClick={action.onClick}>
          {action.label}
        </button>
      )}
      {secondary && <p className="empty-desc">{secondary}</p>}
    </div>
  );
}

export function ErrorState({
  title,
  message,
}: {
  title: string;
  message: string;
}) {
  return (
    <div className="error-box" role="alert">
      <h3>{title}</h3>
      <p>{message}</p>
    </div>
  );
}

export function Field({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <>
      <dt>{label}</dt>
      <dd>{children}</dd>
    </>
  );
}
