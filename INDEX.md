# Blueveil Project Index

> Generated: 2026-09-23
> Status: Step 23-Freeze (release.json)
> Project root: `/workspace/projects/Blueveil`

---

## 1. Project Overview

**Blueveil** is a **private/self-hosted security control plane**. It is **not** a public SaaS, **not** certified for any compliance regime, and operates exclusively on infrastructure you control.

| Property | Value |
|----------|-------|
| Binary | `dist/blueveil` (Go) |
| UI artifact | `collector/ui/dist/` |
| Schema version | 5 (SQLite + PostgreSQL) |
| Contract version | `blueveil.contracts.v1` |
| Toolchains | Go 1.27.1, Rust 1.98.1, Python 3.13.5, Node 26.7.0, PostgreSQL 17.11, protoc 36.1 |

---

## 2. Directory Layout

```
Blueveil/
├── contracts/           # Proto + JSON Schema v1 contract layer
│   ├── proto/blueveil/contracts/v1/   # canonical .proto definitions (8 files)
│   ├── jsonschema/                     # Draft 2020-12 schemas (13 files)
│   ├── fixtures/                       # 29 synthetic test fixtures (15 valid, 14 invalid)
│   └── README.md
├── core/                # Rust core library (blueveil-core)
│   ├── src/
│   │   ├── lib.rs          # crate root, re-exports CoreError
│   │   ├── audit.rs        # append-only audit log
│   │   ├── contracts.rs    # contract boundary validation
│   │   ├── domain.rs       # domain types + CoreError
│   │   ├── events.rs       # in-process event bus
│   │   ├── policy.rs       # minimal policy abstraction
│   │   ├── registry.rs     # extension registry skeleton (ValidationProvider trait)
│   │   └── safety.rs       # safety state skeleton
│   └── target/debug/   # build artifacts
├── collector/           # Go application (main service)
│   ├── cmd/collector/       # CLI entrypoint (main, serve, keygen, seed, backup, version)
│   ├── internal/
│   │   ├── api/             # HTTP handlers + middleware
│   │   ├── asset/           # asset inventory, lifecycle, relationships
│   │   ├── auth/            # bcrypt bearer-key auth
│   │   ├── backup/          # backup/restore/prune engine
│   │   ├── config/          # config model (env/flags/file precedence)
│   │   ├── contract/        # Go-side contract validation (8 .pb.go)
│   │   ├── correlate/       # event correlation
│   │   ├── detect/          # detection engine (rules, registry, threat intel)
│   │   ├── enrich/          # enrichment pipeline
│   │   ├── evidence/        # content-addressed evidence (SHA-256)
│   │   ├── grc/             # governance, risk, compliance (catalog, resilience, architecture)
│   │   ├── identobs/        # identity observation pipeline
│   │   ├── incident/        # incident management
│   │   ├── infraobs/        # infrastructure observation pipeline
│   │   ├── investigate/     # forensics, timeline, threat hunting
│   │   ├── monitor/         # SIEM + query
│   │   ├── netobs/          # network observation pipeline
│   │   ├── normalize/       # event normalization
│   │   ├── obs/             # observability/logging
│   │   ├── perf/            # benchmark harness + workloads
│   │   ├── pipeline/        # detection pipeline (forwarding, staging, incidents)
│   │   ├── response/        # response engine (recommend/approve/execute/verify + safety)
│   │   ├── source/          # source reader + concurrency
│   │   ├── store/           # persistence (audit + campaign store)
│   │   ├── supplychain/     # supply chain model (dependency, vendor, link, history)
│   │   ├── threatintel/     # threat intel IOC
│   │   ├── validation/      # validation engine (runner, provider, executor, campaign)
│   │   └── xlang/           # cross-language bridge tests
│   └── ui/              # TypeScript/React frontend
│       ├── src/
│       │   ├── App.tsx, main.tsx
│       │   ├── api.ts, contracts.ts      # API client + contract parsers
│       │   ├── components/               # Shell, DataTable, FilterBar, StatusTimeline, etc.
│       │   ├── views/                    # Overview, Assets, Incidents, Investigations, Evidence, etc.
│       │   └── theme.tsx, tokens.css
│       ├── e2e/           # Playwright specs (20 tests)
│       └── dist/          # Production build output
├── deploy/              # Deployment artifacts
│   ├── blueveil.service  # systemd unit template
│   ├── install.sh        # installer (--system/--user modes)
│   └── config.example.json
├── docs/                # Documentation
│   ├── OPERATOR.md       # Operator runbook (installation, config, backup, troubleshooting)
│   ├── ATTACK-SURFACE.md # Adversarial attack-surface inventory (Step 20A)
│   ├── PERFORMANCE.md    # Capacity baseline benchmarks (Step 21)
│   └── superpowers/plans/ # Strategic planning docs
├── extensions/          # Polyglot extensions
│   └── python/blueveil_ioc/  # Python IOC library
│       ├── ioc.py, match.py, enrich.py
│       └── tests/             # unittest 21/21
├── dist/                # Built binary output
└── release.json         # Release manifest (step, toolchains, verification status)
```

---

## 3. Core Components

### 3.1 Contracts (`contracts/`)

Canonical boundary definition shared by all components.

| Proto file | Message types |
|------------|---------------|
| `common.proto` | shared enums + messages |
| `telemetry.proto` | `TelemetryEvent` |
| `detection.proto` | `Detection` |
| `alert.proto` | `Alert` |
| `incident.proto` | `Incident` |
| `asset.proto` | `Asset` |
| `evidence.proto` | `Evidence` |
| `identity.proto` | `IdentityObservation` |
| `validation.proto` | `ValidationRequest`, `ValidationResult` |
| `response.proto` | `ResponseRecommendation`, `ResponseApproval`, `ResponseExecution`, `ResponseVerification` |

- **Proto package**: `blueveil.contracts.v1`
- **JSON Schema**: Draft 2020-12, strict (`additionalProperties: false`)
- **Fixtures**: 29 synthetic (15 valid / 14 invalid)
- **Generated Rust**: `blueveil.contracts.v1.rs` (via `prost-build`)

### 3.2 Rust Core (`core/`)

| Module | Responsibility |
|--------|----------------|
| `lib.rs` | Crate root; re-exports `CoreError` |
| `audit.rs` | Append-only audit log skeleton |
| `contracts.rs` | Proto contract validation (`check_*` functions) |
| `domain.rs` | Domain types and `CoreError` enum |
| `events.rs` | In-process event bus |
| `policy.rs` | Minimal policy abstraction |
| `registry.rs` | Extension registry + `ValidationProvider` trait |
| `safety.rs` | Safety state skeleton |

Dependencies: `prost 0.14`, `prost-types 0.14`, `serde_json` (dev)

### 3.3 Go Collector (`collector/`)

The main executable. Single binary (`dist/blueveil`) serving API + UI.

| Subsystem | Package(s) | Purpose |
|-----------|------------|---------|
| CLI | `cmd/collector` | `main`, `serve`, `keygen`, `seed`, `backup`, `restore`, `version` |
| HTTP API | `api/` | Route mux, middleware, observability, identity/investigate/application routes |
| Auth | `auth/` | Bearer API keys (bcrypt), role hierarchy (READ < RESPOND < VALIDATE < ADMIN) |
| Config | `config/` | JSON file + env (`BLUEVEIL_*`) + CLI flags precedence |
| Detection | `detect/` | Rule engine, registry, threat intel, identity/http/network/infra rules |
| Pipeline | `pipeline/` | Staged forwarding, incident detection, response/validation wiring |
| Response | `response/` | Recommend/approve/execute/verify engine, safety policy, audit trail |
| Assets | `asset/` | Inventory manager, lifecycle, relationships, canonicalization, discovery |
| Validation | `validation/` | Runner, provider registry, executor, campaign, purple team |
| Evidence | `evidence/` | Content-addressed storage with SHA-256 digest verification |
| Incidents | `incident/` | Incident management with concurrency control |
| GRC | `grc/` | Governance catalog, resilience, architecture model |
| Supply Chain | `supplychain/` | Dependency, vendor, link, history, continuous monitoring |
| Backup | `backup/` | SQLite `VACUUM INTO` and PostgreSQL `pg_dump`/`psql` engine |
| Store | `store/` | Persistence layer (SQLite/PostgreSQL), audit + campaign stores |
| Observations | `infraobs/`, `identobs/`, `netobs/`, `httpobs/` | Observation pipelines with redaction sinks + correlation |
| Enrichment | `enrich/` | Event enrichment pipeline |
| Monitoring | `monitor/` | SIEM integration + query |
| Normalize | `normalize/` | Event normalization |
| Investigate | `investigate/` | Forensics, timeline, threat hunting |
| Threat Intel | `threatintel/` | IOC processing |
| Correlate | `correlate/` | Event correlation |
| Invariants | `invariants/` | Cross-cutting invariant checks |
| Perf | `perf/` | Benchmark harness + workload generators |
| Contracts | `contract/` | Go-side contract validation (generated `.pb.go` + hand-written `Validate*`) |

Direct Go dependencies:
- `github.com/jackc/pgx/v5 v5.11.0`
- `golang.org/x/crypto v0.57.0`
- `google.golang.org/protobuf v1.36.12`
- `modernc.org/sqlite v1.58.0`

### 3.4 React UI (`collector/ui/`)

Vite + React 19 + TypeScript. Served as static assets by the Go binary.

| Path | Content |
|------|---------|
| `src/api.ts` | Fetch wrapper with Bearer auth |
| `src/contracts.ts` | Frontend contract parsers |
| `src/components/` | Shell, DataTable, FilterBar, StatusTimeline, StatusBadge, Drawer, StatCard, SummaryStrip, CommandPalette, States |
| `src/views/` | Overview, Assets, Incidents, Investigations, Evidence, Validation, Responses, Network, SupplyChain, Application, Infrastructure, Governance, Identity, ReportView, Monitoring, Findings |
| `src/theme.tsx`, `tokens.css` | Design system |

Test suites: 73 vitest unit + 20 Playwright e2e.

### 3.5 Python Extensions (`extensions/python/`)

Stdlib-only IOC library:

| Module | Responsibility |
|--------|----------------|
| `ioc.py` | IOC model |
| `match.py` | Deterministic offline indicator matching |
| `enrich.py` | Enrichment (adds facts, never verdicts) |
| `__main__.py` | CLI entry |

Tests: 21/21 unittest.

---

## 4. Key Operations & APIs

### 4.1 CLI Commands (`cmd/collector`)

| Command | Description |
|---------|-------------|
| `blueveil --serve` | Start API + UI server |
| `blueveil --seed --db <path>` | Seed lab dataset |
| `blueveil --keygen --key-id X --key-role READ` | Generate bcrypt API key (secret via stdin) |
| `blueveil --backup --config C --backup-out DIR` | Backup (SQLite `VACUUM INTO` / PG `pg_dump`) |
| `blueveil --restore --config C --restore-from DIR [--restore-dbname NAME]` | Restore into isolated target |
| `blueveil --prune-backups --prune-dir DIR --keep N` | Retain N most recent backups |
| `blueveil --version` | Print build info |

### 4.2 HTTP Endpoints

| Method | Path | Role | Description |
|--------|------|------|-------------|
| GET | `/api/v1/healthz` | public | Liveness probe |
| GET | `/api/v1/readyz` | public | Readiness probe (DB + schema) |
| GET | `/api/v1/*` | READ | All read routes |
| POST | `/api/v1/assets/observations` | RESPEND | Ingest asset observation |
| PATCH | `/api/v1/assets/{id}/lifecycle` | ADMIN | Update asset lifecycle |

Auth: `Authorization: Bearer <key>`. Roles: `READ < RESPOND < VALIDATE < ADMIN`.

### 4.3 Install Modes

**System** (needs root once):
```
sudo ./deploy/install.sh --system --backend postgres --listen 127.0.0.1:8008
```

**User** (no root):
```
./deploy/install.sh --user --prefix ~/blueveil --backend sqlite
```

---

## 5. Configuration

Single config model (`collector/internal/config`):

Precedence (lowest → highest):
1. Compiled lab defaults
2. JSON file (`--config` / `BLUEVEIL_CONFIG_FILE`)
3. `BLUEVEIL_*` environment variables
4. CLI flags (operational surface only)

Secrets travel by env/file only (never argv):
- `BLUEVEIL_PG_PASSWORD` — database password
- `BLUEVEIL_API_KEYS` — JSON array of `{id, role, hash, expires_at?}`

Key fields:
- `env`: lab | production
- `listen_addr`: default `127.0.0.1:8008` (lab requires loopback)
- `database.backend`: sqlite | postgres
- `tls.enabled/cert_file/key_file/min_version`: default off (lab), TLS 1.3 (prod)
- `auth.enabled/keys`: bearer keys with bcrypt hashes
- `logging.level/format`: debug|info|warn|error, text|json

---

## 6. Database Schema

| Property | SQLite | PostgreSQL |
|----------|--------|------------|
| Backend | `modernc.org/sqlite` (WAL) | `pg/v5` pool |
| Migrations | Forward-only, transactional (v1→v5) | Same |
| Refusal | Future/unknown versions refused | Same |
| Backup | `VACUUM INTO` (online, consistent) | `pg_dump --no-owner --no-privileges` |
| Restore | Copy into empty path | `psql` into empty database, count + digest verified |

---

## 7. Performance Baseline (Step 21)

Measured on 2 vCPU / 6.9 GB RAM / SSD / Debian 13:

| Metric | Value |
|--------|-------|
| API mixed read throughput (SQLite) | ~100-120 rps |
| API mixed read throughput (PG) | ~137 rps |
| Telemetry ingest rate | 10-500/s, zero silent drops |
| Detection engine | ~110k events/s single-threaded |
| Backup/restore (460 rows) | ~0.36s / ~0.37s |
| Memory RSS | 22-27 MB settling |
| Per-request auth (bcrypt MinCost) | ~5.3 ms |

Bottlenecks:
1. Full-table protojson marshal on telemetry-family reads
2. Per-request bcrypt (intentional security cost)
3. SQLite single-writer lock (PG backend is the answer)

---

## 8. Security Model

| Boundary | Defense |
|----------|---------|
| Network | Private LAN/VPN/loopback only; no public SaaS |
| Auth | Bearer API keys (bcrypt hashes only stored) |
| AuthZ | Role hierarchy gates HTTP reachability; Safety Policy governs actions |
| TLS | 1.2/1.3, terminates at Blueveil or upstream |
| Evidence | Content-addressed SHA-256, verified on every read |
| Audit | Append-only, no update/delete surface |
| Backup | Marker scan (rejects secrets in plaintext) |

**No brute-force lockout** — uniform 401s + private network is the design.

---

## 9. Testing

| Suite | Tooling | Count |
|-------|---------|-------|
| Go unit + integration | `go test` + `race` | 28 packages |
| Rust | `cargo test` + clippy | 28 + contract_boundary |
| Python | unittest | 21/21 |
| UI unit | vitest | 73 |
| UI e2e | Playwright | 20 |
| Install | live systemd | user scope tested |
| Contract fixtures | proto + jsonschema | 29 fixtures |

Known limitations (from release.json):
- System-scope install not tested (no root in CI)
- Second-peer LAN/VPN untested
- Cross-version upgrade untested from single checkout
- No open-ended fuzzing (bounded corpus instead)

---

## 10. Out of Scope (Explicitly)

- HA / failover / clustering
- Kubernetes / Docker requirement
- OAuth / SSO / IAM / enterprise SSO
- External SIEM / threat-intel services
- Public SaaS infrastructure
- Brute-force lockout
- Any compliance certification

---

## 11. Reference Docs

| File | Content |
|------|---------|
| `docs/OPERATOR.md` | Complete operator runbook (install, config, auth, backup, recovery) |
| `docs/ATTACK-SURFACE.md` | Attack-surface inventory for adversarial testing |
| `docs/PERFORMANCE.md` | Capacity baseline and benchmark methodology |
| `contracts/README.md` | Contract versioning, proto↔JSON mapping, fixtures |
| `extensions/README.md` | Extension boundary rules and language status |
| `release.json` | Release manifest (step, toolchains, verification, known limitations) |
