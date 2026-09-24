import { useMemo, useState } from "react";

export interface Column<T> {
  key: string;
  header: string;
  numeric?: boolean;
  sortable?: boolean;
  sortValue?: (row: T) => string | number;
  render: (row: T) => React.ReactNode;
}

// Minimal sortable table (sticky header, restrained hover). Sorting is
// client-side over the fetched list — datasets here are lab-scale, so no
// table engine dependency is warranted.
export function DataTable<T extends { id: string }>({
  columns,
  rows,
  onRowClick,
  rowLabel,
  empty,
  initialSortKey = null,
  initialSortDir = 1,
}: {
  columns: Column<T>[];
  rows: T[];
  onRowClick?: (row: T) => void;
  rowLabel?: (row: T) => string;
  empty: React.ReactNode;
  initialSortKey?: string | null;
  initialSortDir?: 1 | -1;
}) {
  const [sortKey, setSortKey] = useState<string | null>(initialSortKey);
  const [dir, setDir] = useState<1 | -1>(initialSortDir);
  const sorted = useMemo(() => {
    if (!sortKey) return rows;
    const col = columns.find((c) => c.key === sortKey);
    if (!col?.sortable) return rows;
    const get =
      col.sortValue ??
      ((r: T) => String((r as Record<string, unknown>)[col.key] ?? ""));
    return [...rows].sort((a, b) => {
      const av = get(a);
      const bv = get(b);
      if (av < bv) return -1 * dir;
      if (av > bv) return 1 * dir;
      return 0;
    });
  }, [rows, sortKey, dir, columns]);
  if (rows.length === 0) return <>{empty}</>;
  return (
    <div className="table-wrap">
      <table className="data">
        <thead>
          <tr>
            {columns.map((c) => (
              <th
                key={c.key}
                className={`${c.numeric ? "num" : ""}${c.sortable ? " sortable" : ""}`}
                aria-sort={
                  sortKey === c.key
                    ? dir === 1
                      ? "ascending"
                      : "descending"
                    : undefined
                }
                onClick={
                  c.sortable
                    ? () => {
                        if (sortKey === c.key)
                          setDir((d) => (d === 1 ? -1 : 1));
                        else {
                          setSortKey(c.key);
                          setDir(1);
                        }
                      }
                    : undefined
                }
              >
                {c.header}
                {sortKey === c.key && (
                  <span aria-hidden="true"> {dir === 1 ? "↑" : "↓"}</span>
                )}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sorted.map((row) => (
            <tr
              key={row.id}
              className={onRowClick ? "rowlink rise" : undefined}
              onClick={onRowClick ? () => onRowClick(row) : undefined}
              aria-label={rowLabel?.(row)}
            >
              {columns.map((c) => (
                <td key={c.key} className={c.numeric ? "num" : undefined}>
                  {c.render(row)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
