// Hand-drawn inline SVG set (no icon dependency). stroke=currentColor,
// 1.5 width, 16px box. Add icons here only when a view needs one.
const base = {
  width: 16,
  height: 16,
  viewBox: "0 0 16 16",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.5,
  strokeLinecap: "round",
  strokeLinejoin: "round",
} as const;

export const icons = {
  shield: (
    <svg {...base}>
      <path d="M8 1.5 13 3.5v4c0 3.2-2.1 5.4-5 6.5-2.9-1.1-5-3.3-5-6.5v-4L8 1.5Z" />
      <path d="M5.8 7.6l1.6 1.6 2.8-3" />
    </svg>
  ),
  overview: (
    <svg {...base}>
      <rect x="1.5" y="1.5" width="5.5" height="5.5" rx="1" />
      <rect x="9" y="1.5" width="5.5" height="5.5" rx="1" />
      <rect x="1.5" y="9" width="5.5" height="5.5" rx="1" />
      <rect x="9" y="9" width="5.5" height="5.5" rx="1" />
    </svg>
  ),
  findings: (
    <svg {...base}>
      <circle cx="7" cy="7" r="4.5" />
      <path d="M10.5 10.5 14.5 14.5" />
    </svg>
  ),
  incidents: (
    <svg {...base}>
      <path d="M8 1.8 14.2 13.5H1.8L8 1.8Z" />
      <path d="M8 6v3.2" />
      <circle cx="8" cy="11.4" r="0.2" fill="currentColor" />
    </svg>
  ),
  governance: (
    <svg {...base}>
      <path d="M3 13.5V8M8 13.5V2.5M13 13.5V5.5" />
      <path d="M1.5 13.5h13" />
    </svg>
  ),
  "supply-chain": (
    <svg {...base}>
      <circle cx="3" cy="3" r="1.8" />
      <circle cx="13" cy="3" r="1.8" />
      <circle cx="8" cy="13" r="1.8" />
      <path d="M4.5 4.2 6.8 11.5M11.5 4.2 9.2 11.5M4.8 3h6.4" />
    </svg>
  ),
  assets: (
    <svg {...base}>
      <circle cx="3.5" cy="8" r="2" />
      <circle cx="12.5" cy="4" r="2" />
      <circle cx="12.5" cy="12" r="2" />
      <path d="M5.3 7.2 10.7 4.8M5.3 8.8l5.4 2.4" />
    </svg>
  ),
  evidence: (
    <svg {...base}>
      <path d="M4 1.8h5.5L12.5 5v9.2H4V1.8Z" />
      <path d="M9.3 1.8V5H12.5" />
      <path d="M6 8h4M6 10.2h4" />
    </svg>
  ),
  report: (
    <svg {...base}>
      <path d="M4 1.8h5.5L12.5 5v9.2H4V1.8Z" />
      <path d="M9.3 1.8V5H12.5" />
      <path d="M6 8h4M6 10.2h2.5" />
      <circle cx="10.2" cy="11" r="1.6" />
    </svg>
  ),
  validation: (
    <svg {...base}>
      <path d="M2.5 8.5 6 12l7.5-8" />
    </svg>
  ),
  responses: (
    <svg {...base}>
      <path d="M2.5 8h3l1.5-4 3 8 1.5-4h2" />
    </svg>
  ),
  search: (
    <svg {...base}>
      <circle cx="7" cy="7" r="4.5" />
      <path d="M10.5 10.5 14.5 14.5" />
    </svg>
  ),
  sun: (
    <svg {...base}>
      <circle cx="8" cy="8" r="3" />
      <path d="M8 1.5v1.6M8 12.9v1.6M1.5 8h1.6M12.9 8h1.6M3.4 3.4l1.1 1.1M11.5 11.5l1.1 1.1M12.6 3.4l-1.1 1.1M4.5 11.5l-1.1 1.1" />
    </svg>
  ),
  moon: (
    <svg {...base}>
      <path d="M13.5 9.5A5.5 5.5 0 0 1 6.5 2.5a5.5 5.5 0 1 0 7 7Z" />
    </svg>
  ),
  chevron: (
    <svg {...base}>
      <path d="M6 3.5 10.5 8 6 12.5" />
    </svg>
  ),
  x: (
    <svg {...base}>
      <path d="M3.5 3.5l9 9M12.5 3.5l-9 9" />
    </svg>
  ),
  panel: (
    <svg {...base}>
      <rect x="1.5" y="2.5" width="13" height="11" rx="1.5" />
      <path d="M6 2.5v11" />
    </svg>
  ),
  triangle: (
    <svg {...base}>
      <path d="M8 2 14.5 13.5h-13L8 2Z" />
    </svg>
  ),
  network: (
    <svg {...base}>
      <rect x="1.5" y="6" width="13" height="5" rx="1.2" />
      <circle cx="5" cy="8.5" r="1" fill="currentColor" />
      <circle cx="11" cy="8.5" r="1" fill="currentColor" />
      <path d="M6 8.5h4" />
    </svg>
  ),
  application: (
    <svg {...base}>
      <rect x="1.5" y="3" width="13" height="10" rx="1.2" />
      <path d="M1.5 6h13" />
      <circle cx="3.5" cy="4.5" r="0.7" fill="currentColor" />
      <circle cx="5.5" cy="4.5" r="0.7" fill="currentColor" />
      <path d="M4 9h4M4 11h6" />
    </svg>
  ),
  infrastructure: (
    <svg {...base}>
      <rect x="3" y="2" width="10" height="3" rx="0.8" />
      <rect x="3" y="6.5" width="10" height="3" rx="0.8" />
      <rect x="3" y="11" width="10" height="3" rx="0.8" />
      <circle cx="5" cy="3.5" r="0.6" fill="currentColor" />
      <circle cx="5" cy="8" r="0.6" fill="currentColor" />
      <circle cx="5" cy="12.5" r="0.6" fill="currentColor" />
    </svg>
  ),
  monitoring: (
    <svg {...base}>
      <circle cx="7" cy="7" r="4.5" />
      <path d="M10.5 10.5 14.5 14.5" />
      <path d="M7 4.5v2.5l1.7 1.7" />
    </svg>
  ),
  identity: (
    <svg {...base}>
      <circle cx="8" cy="5" r="2.6" />
      <path d="M2.8 13.5c.6-2.8 2.7-4.2 5.2-4.2s4.6 1.4 5.2 4.2" />
    </svg>
  ),
  investigations: (
    <svg {...base}>
      <path d="M2.5 4.5h11" />
      <circle cx="11.5" cy="4.5" r="1.6" />
      <path d="M2.5 8.5h7" />
      <circle cx="8" cy="8.5" r="1.6" />
      <path d="M2.5 12.5h4" />
      <circle cx="5" cy="12.5" r="1.6" />
    </svg>
  ),
};

export type IconName = keyof typeof icons;

export function Icon({ name, label }: { name: IconName; label?: string }) {
  if (label) {
    return (
      <span role="img" aria-label={label} style={{ display: "inline-flex" }}>
        {icons[name]}
      </span>
    );
  }
  return (
    <span aria-hidden="true" style={{ display: "inline-flex" }}>
      {icons[name]}
    </span>
  );
}
