import { useEffect, useMemo, useRef, useState } from "react";
import { Icon } from "../icons";

export interface PaletteItem {
  id: string;
  group: string;
  label: string;
  hint?: string;
  run: () => void;
}

// Command palette (D): Ctrl/⌘K overlay, grouped items, arrow-key nav,
// Enter to jump, Esc to dismiss. Hand-rolled (~100 lines, no cmdk/radix).
export function CommandPalette({
  open,
  onClose,
  items,
}: {
  open: boolean;
  onClose: () => void;
  items: PaletteItem[];
}) {
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    const list = q
      ? items.filter(
          (i) =>
            i.label.toLowerCase().includes(q) ||
            (i.hint ?? "").toLowerCase().includes(q),
        )
      : items;
    const order = new Map<string, number>();
    list.forEach((i) => {
      if (!order.has(i.group)) order.set(i.group, order.size);
    });
    return [...list].sort(
      (a, b) => (order.get(a.group) ?? 0) - (order.get(b.group) ?? 0),
    );
  }, [items, query]);
  useEffect(() => {
    if (open) {
      setQuery("");
      setActive(0);
      setTimeout(() => inputRef.current?.focus(), 0);
    }
  }, [open]);
  useEffect(() => setActive(0), [query]);
  if (!open) return null;
  const groups: {
    name: string;
    items: { item: PaletteItem; index: number }[];
  }[] = [];
  filtered.forEach((item) => {
    const index = items.indexOf(item);
    let g = groups.find((x) => x.name === item.group);
    if (!g) {
      g = { name: item.group, items: [] };
      groups.push(g);
    }
    g.items.push({ item, index });
  });
  // active indexes into filtered
  return (
    <div className="palette-overlay" onClick={onClose}>
      <div
        className="palette"
        role="dialog"
        aria-modal="true"
        aria-label="Command palette"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="palette-input-row">
          <Icon name="search" />
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Jump to a view, finding, or incident…"
            aria-label="Search commands, findings, incidents"
            onKeyDown={(e) => {
              if (e.key === "ArrowDown") {
                e.preventDefault();
                setActive((a) => Math.min(a + 1, filtered.length - 1));
              } else if (e.key === "ArrowUp") {
                e.preventDefault();
                setActive((a) => Math.max(a - 1, 0));
              } else if (e.key === "Enter") {
                const pick = filtered[active];
                if (pick) {
                  pick.run();
                  onClose();
                }
              } else if (e.key === "Escape") {
                onClose();
              }
            }}
          />
          <span className="kbd">ESC</span>
        </div>
        <div className="palette-list" role="listbox" aria-label="Results">
          {filtered.length === 0 && (
            <div className="palette-empty">No results found.</div>
          )}
          {groups.map((g) => (
            <div key={g.name}>
              <div className="palette-group">{g.name}</div>
              {g.items.map(({ item }) => {
                const flat = filtered.indexOf(item);
                return (
                  <button
                    key={item.id}
                    role="option"
                    aria-selected={flat === active}
                    className={`palette-item${flat === active ? " active" : ""}`}
                    onMouseEnter={() => setActive(flat)}
                    onClick={() => {
                      item.run();
                      onClose();
                    }}
                  >
                    <span style={{ flex: 1 }}>{item.label}</span>
                    {item.hint && (
                      <span
                        style={{ color: "var(--bv-muted)", fontSize: 12 }}
                        className="mono"
                      >
                        {item.hint}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
