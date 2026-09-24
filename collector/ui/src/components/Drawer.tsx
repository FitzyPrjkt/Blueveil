import { useEffect, useRef } from "react";
import { Icon } from "../icons";

// Detail drawer (H): right slide-over, Esc close, overlay click close,
// initial focus into the panel. Hand-rolled (no radix dependency).
export function Drawer({
  title,
  onClose,
  children,
}: {
  title: React.ReactNode;
  onClose: () => void;
  children: React.ReactNode;
}) {
  const panelRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    panelRef.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <>
      <div className="drawer-overlay" onClick={onClose} aria-hidden="true" />
      <div
        className="drawer"
        role="dialog"
        aria-modal="true"
        aria-label={typeof title === "string" ? title : "Details"}
        ref={panelRef}
        tabIndex={-1}
      >
        <div className="drawer-head">
          <h2 className="drawer-title" style={{ flex: 1 }}>
            {title}
          </h2>
          <button
            className="icon-btn"
            onClick={onClose}
            aria-label="Close details"
          >
            <Icon name="x" />
          </button>
        </div>
        <div className="drawer-body">{children}</div>
      </div>
    </>
  );
}
