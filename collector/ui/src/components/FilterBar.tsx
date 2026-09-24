import { Icon } from "../icons";

// Filter toolbar (J): search input + labeled native selects + clear.
// Only filters the view wires up are rendered — never speculative ones.
export interface FilterOption {
  value: string;
  label: string;
}

export function FilterBar({
  search,
  onSearch,
  searchLabel,
  searchPlaceholder,
  selects,
  onClear,
  hasActive,
}: {
  search: string;
  onSearch: (v: string) => void;
  searchLabel: string;
  searchPlaceholder: string;
  selects: {
    label: string;
    value: string;
    options: FilterOption[];
    onChange: (v: string) => void;
  }[];
  onClear: () => void;
  hasActive: boolean;
}) {
  return (
    <div className="filterbar" role="search">
      <label className="search-input">
        <Icon name="search" />
        <span className="sr-only">{searchLabel}</span>
        <input
          value={search}
          onChange={(e) => onSearch(e.target.value)}
          placeholder={searchPlaceholder}
          aria-label={searchLabel}
        />
      </label>
      {selects.map((s) => (
        <label
          key={s.label}
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: 6,
            fontSize: 13,
            color: "var(--bv-muted)",
          }}
        >
          {s.label}
          <select
            className="select"
            value={s.value}
            onChange={(e) => s.onChange(e.target.value)}
            aria-label={s.label}
          >
            {s.options.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
        </label>
      ))}
      {hasActive && (
        <button className="btn" onClick={onClear}>
          Clear
        </button>
      )}
    </div>
  );
}
