# Blueveil — self-hosted security control plane

Blueveil is a **self-hosted security control plane**: telemetry in, detections
out, with incidents, digest-verified evidence, safety-gated responses,
validation campaigns, governance posture, supply-chain visibility, and a
one-click posture report — all on infrastructure you control.

> **Honest scope.** Blueveil is lab-grade open source, not a certified
> product. It claims no compliance regime (SOC 2, ISO 27001, PCI DSS), makes
> no "secure/safe" verdicts, and every empty state says what it doesn't know.
> Run it, read the code, verify the claims yourself.

## What it does

- **Observe** — normalize telemetry into contract-valid events (Go collector)
- **Detect** — deterministic rules over telemetry (Rust core + Go engine)
- **Respond** — safety-gated recommendations: approvals, execution, verification
- **Validate** — campaigns + purple-team exercises with verbatim outcomes
- **Govern** — GRC controls, assessments, resilience posture, exceptions
- **Supply chain** — components, SBOMs, policies, vendors, continuous checks
- **Report** — executive + full posture report, print-ready, hash-identified

## Quickstart (5 minutes, local only)

Prerequisites: Go 1.27+, Node 20+, SQLite (built in, no server needed).

```bash
# 1. Build
cd collector && go build -o /tmp/blueveil ./cmd/collector
cd ui && npm ci && npm run build && cd ..

# 2. Seed a synthetic lab dataset (labeled, local-only)
./path/to/blueveil --seed --db /tmp/lab.db

# 3. Serve (loopback only) with the built UI
./path/to/blueveil --serve --db /tmp/lab.db \
  --addr 127.0.0.1:8008 --ui-dir ./ui/dist
```

Open http://127.0.0.1:8008 — Overview, 15 workspaces, Report. No accounts,
no telemetry leaves your machine (lab mode binds loopback and uses only
synthetic `seed-lab-*` data).

Production deploys (TLS, API keys, PostgreSQL, systemd, backups) are covered
in [`docs/OPERATOR.md`](docs/OPERATOR.md) and [`deploy/`](deploy/).

## Repository layout

```
Blueveil/
├── collector/      # Go service: API, detection, store (SQLite/Postgres),
│                   #   responses/safety, backup/restore, UI server + ui/
│   └── ui/         # React workstation (read-only over the API)
├── core/           # Rust detection core
├── contracts/      # Canonical .proto + JSON Schema + fixtures (v1)
├── extensions/     # Python IOC utilities (stdlib only)
├── deploy/         # systemd unit, install script, config template
└── docs/           # Operator runbook, attack surface, performance notes
```

## Verify it yourself

```bash
cd collector && go vet ./... && go test ./...      # Go
cd ../core && cargo test                            # Rust
cd ../collector/ui && npm test && npm run build     # UI (vitest + tsc + vite)
cd ../../extensions/python && python3 -m unittest   # Python
```

CI runs all four on every push ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)).

## Design rules (the short version)

- **Deterministic**: same data in → same output out. No AI in the pipeline.
- **Honest states**: `UNKNOWN`, `NOT_ASSESSED`, `NOT_TESTED` instead of invented verdicts.
- **Fail-closed safety**: responses require approval + verification; denials are explicit.
- **Evidence integrity**: SHA-256 envelope; unverified rows never render as verified.
- **Local-first**: lab mode is loopback-only with synthetic data; nothing phones home.

## Contributing

Issues and PRs welcome. Keep the rules above: deterministic, honest,
tested. Run the four verification commands before opening a PR — CI will
anyway. See [`SECURITY.md`](SECURITY.md) for reporting vulnerabilities
(privately, please).

## License

MIT — see [`LICENSE`](LICENSE).
