# collector (Go skeleton, Step 4)

In-process telemetry collector: `Source → Normalizer → Sink`, emitting only
contract-valid `TelemetryEvent`. Observe → normalize → emit. No detection,
no alerting, no persistence, no network.

Module path `blueveil/collector` is provisional until the Blueveil repo
remote is decided; it claims no registry or domain.

## Layout

```
collector/
├── go.mod / go.sum
├── README.md (this file)
├── cmd/collector/main.go      --self-test [--emit-jsonl PATH] (verification only)
└── internal/
    ├── contract/              boundary validation + canonical JSON (MarshalCanonical/UnmarshalStrict)
    │   └── v1/                GENERATED from ../contracts/proto — DO NOT EDIT
    ├── source/                Source interface + ChannelSource (in-memory)
    │                          + ReaderSource (JSON-lines file/stdin lab source)
    ├── normalize/             RawEvent -> TelemetryEvent (typed errors, no invented data)
    ├── enrich/                deterministic collection metadata (blueveil.* keys only)
    ├── correlate/             stable correlation ids (metadata only, no inference)
    └── pipeline/              Config + Pipeline + InMemorySink + LineSink + Report/Metrics
```

Tests are colocated `*_test.go` per Go convention (no separate `tests/` dir).

## Contract codegen (no .proto modification)

`.proto` files carry no `go_package` option (kept language-neutral), so the
import path is supplied per file with `M` flags:

```sh
export PATH="$HOME/sdk/go/bin:$HOME/go/bin:$PATH"
P=/workspace/projects/Blueveil/contracts/proto
G=/workspace/projects/Blueveil/collector/internal/contract/v1
GEN=$(mktemp -d)
"$HOME/.local/protoc-36.1/bin/protoc" -I$P -I"$HOME/.local/protoc-36.1/include" \
  --plugin=protoc-gen-go="$HOME/go/bin/protoc-gen-go" \
  --go_out=$GEN --go_opt=paths=source_relative \
  --go_opt=Mblueveil/contracts/v1/common.proto=blueveil/collector/internal/contract/v1 \
  --go_opt=Mblueveil/contracts/v1/asset.proto=blueveil/collector/internal/contract/v1 \
  --go_opt=Mblueveil/contracts/v1/identity.proto=blueveil/collector/internal/contract/v1 \
  --go_opt=Mblueveil/contracts/v1/telemetry.proto=blueveil/collector/internal/contract/v1 \
  --go_opt=Mblueveil/contracts/v1/detection.proto=blueveil/collector/internal/contract/v1 \
  --go_opt=Mblueveil/contracts/v1/evidence.proto=blueveil/collector/internal/contract/v1 \
  --go_opt=Mblueveil/contracts/v1/validation.proto=blueveil/collector/internal/contract/v1 \
  $P/blueveil/contracts/v1/*.proto
mv $GEN/blueveil/contracts/v1/*.pb.go $G/
```

`protoc-gen-go` (v1.36.12, in `~/go/bin`) is a codegen TOOL, not a runtime
dependency. Runtime needs only `google.golang.org/protobuf` (generated-code
runtime + protojson); see `go.mod`.

## Telemetry pipeline (Step 5)

Flow: `ReaderSource | ChannelSource → Pipeline → Normalizer → Enricher
(optional) → Correlation (optional) → Sink (memory | protojson-lines)`.

- **ReaderSource**: one JSON object per line (`id, source, asset_id,
  identity_id, event_type, severity, attributes, raw, occurred_at` RFC 3339).
  Malformed lines never enter the pipeline; they surface as `SourceErrors`
  in the report with 1-based line numbers.
- **Enrichment** adds exactly `blueveil.collector` + `blueveil.collected_at`
  (RFC 3339, clock-provided). It never overwrites source keys and never
  invents values (zero clock = error). No lookups, no intel, no inference.
- **Correlation** stamps `blueveil.correlation_id` = first-16-hex of
  SHA-256 over `source|asset_id|event_type`. Same triple → same id, every
  run, every process. Source-provided ids win. Association only.
- **Backpressure**: the internal queue is bounded (`Config.QueueSize`);
  saturation blocks the sender — never drops. Cancellation stops intake,
  drains the queue, returns the full report.
- **Metrics** (`Report.Metrics`): received/accepted/rejected, per-stage
  error counters, total/max/avg handle latency. In-memory only.
- **Interop boundary**: `LineSink` emits canonical protojson
  (`UseProtoNames`, one event per line). The Rust core consumes these bytes
  (`core/tests/telemetry_intake.rs` via `BLUEVEIL_TELEMETRY_JSONL`) through
  its real descriptor + `InProcessBus`. No broker, no RPC.

## Detection layer (Step 6)

`internal/detect`: `TelemetryEvent → Rule Registry → Engine → Detection →
Alert`, all on generated protobuf types. Detection is observation data, not
authorization: a match never blocks, isolates, or executes anything.

- **Rules** (`Rule{id, version, name, description, evaluate}`): deterministic,
  stdlib-only. Initial three, all severity-inherited (never above the source
  rating) and confidence `0.0` = unmeasured boolean (documented in-band via
  `blueveil.confidence_basis`, never fabricated):
  - `waf-block-high-severity` v1 (stateless): blocked + source HIGH/CRITICAL.
  - `waf-block-burst` v1 (stateful): ≥threshold blocked per asset within
    window (event-time windows, local explicit state, fires once per
    crossing, re-arms below threshold).
  - `source-declared-critical` v1 (stateless): any source CRITICAL.
- **Engine**: contract-validates input (invalid → `ErrInvalidTelemetry`,
  no rule runs); rule errors abort loudly (`ErrRuleEvaluation`, zero output —
  never a false no-match); deterministic detection ids
  (`det-` + digest of rule + sorted event ids); 1:1 deterministic alerts
  (`alert-` + detection id, status OPEN); in-memory dedup set (restart
  clears it — documented limit); builder rejects `blueveil.*` rule attrs.
- **Pipeline stage**: `DetectingSink{Engine, Downstream, Store}` — detects,
  stores new pairs, forwards the original event; detection failure aborts
  the run (`ErrDetection`, fail-closed).
- **Safety boundary**: no response/recommendation/action vocabulary anywhere
  in this package; grep the sources — only scope-disclaimer comments match.

## Incident & evidence layer (Step 7)

`internal/incident` + `internal/evidence`: `Alert → Incident → Evidence`,
passive and data-only (observe, correlate, record, validate, hash — never
execute, block, or remediate). No persistence; in-memory only.

- **Incident**: built from one alert + its detection + contributing events.
  Id deterministic (`inc-` + digest of the correlation key); severity =
  max attached alert; title/summary derived from observed data only.
  Correlation prefers the explicit `blueveil.correlation_id` shared by all
  contributors, else the safe 1-alert→1-incident baseline — no heuristic
  merging. Lifecycle is linear `OPEN→INVESTIGATING→CONTAINED→RESOLVED→
  CLOSED`; anything else is an explicit error. Re-ingest is idempotent.
- **Evidence**: one `LOG_EXCERPT` per contributing event plus one `NOTE`
  each for the detection and the alert; content is always the canonical
  serialization of the real object. Digest = hex SHA-256 (stdlib);
  `Verify` recomputes it (integrity check, not tamper-proof storage).
- **Pipeline stage**: `IncidentSink{Engine, Manager, Evidence, Detections,
  Archive, Downstream}` supersedes `DetectingSink` where incidents are
  wanted; archive resolves contributing events by id (missing = explicit
  error, never fabricated); incident/evidence failures abort the run.

## Response layer (Step 8)

`internal/response`: incident data in, authorized and verified outcomes out —
recommend → decide (policy) → approve (if required) → execute → verify,
auditing every step. Fail-closed; detection ≠ authorization.

- **Contract** (additive, `response.proto` + 4 schemas + 8 fixtures):
  `ResponseRecommendation/Approval/Execution/Verification` with
  `OperationType`, `RiskLevel`, `ResponseStatus`, `VerificationOutcome`.
  No existing message touched. No SUCCESS/SECURE/PASS values exist.
- **Policy**: `Allow/Deny/RequireApproval`, mirroring the Rust core.
  Fail-closed: unknown operation/risk/actor DENY; destructive ops and
  HIGH/CRITICAL always need approval. Policy non-objection is not gate
  passage: HIGH under Allow still parks for a human.
- **Safety**: 1:1 port of `core/src/safety.rs` (same states, order, gates);
  entering EXECUTE always presents the approval gate once authorization is
  established — what varies is what established it (policy vs bound approval).
- **Approval**: bound to one recommendation (id+operation+target+risk),
  expirable, single-use via the engine; mismatched/expired/replayed reject.
  Test actors are synthetic and labeled (`test-actor:*`).
- **Executor**: simulated in-memory only — records requests, returns
  programmed outcomes, zero real-world effects by construction. No shell,
  no subprocess, no firewall, no cloud, anywhere in the tree.
- **Verification**: `VERIFIED/FAILED/UNKNOWN`; failed executions verify
  FAILED; the honest default without a source is UNKNOWN, never VERIFIED.
- **Audit**: every decision appended with actor/operation/risk/timestamp/
  reason/result + response id + phase; in-memory, explicitly not tamper-proof.
- **Pipeline boundary**: the telemetry pipeline stops at evidence. Response
  runs via explicit engine calls (tested in `pipeline/response_test.go` and
  the self-test) — never automatic execution.

## Validation layer (Step 9)

`internal/validation`: `ValidationRequest → ValidationProvider →
ValidationResult`, reachable only inside the response engine's execute step
(`ValidationExecutor` adapts provider→executor). Validation never bypasses
policy, approval, gate, or audit — bypass is structurally impossible.

- **Contract**: Step-2 `ValidationRequest/Result` + 8-verdict enum reused
  unchanged (Go validators added; Rust checks pre-existed). No SECURE.
  `NOT_TESTED` ≠ `ALLOWED_AND_NOT_DETECTED` ≠ `UNKNOWN`, enforced by tests.
- **Request**: built only from incident/alert/detection/events. `control_id`
  comes from telemetry `control_id`/`rule_id` attributes; absent → explicit
  construction error, never an invented control. Target = observed assets.
- **Registry**: register/get/list (sorted), duplicates/nil/empty rejected.
  No dynamic loading.
- **Native provider**: scripted deterministic verdicts per control
  (test-labeled, never production validation); error double stays an error.
- **Redveil adapter**: optional boundary, zero Redveil imports/deps.
  Unavailable (this environment: CLI present, no provider API/service) →
  contract-valid `NOT_TESTED`, never success, never error-for-absence.
  Provider crashes stay errors. No process is spawned in this step.
- **Executor binding**: engine target must equal the bound target; request
  identity (request/control ids) and contract version enforced on output;
  invalid output rejected with nothing stored. `NOT_TESTED` verdict →
  execution `Success=false`; other verdicts → `Success=true` (provider ran;
  the verdict says what it found). Evidence NOTE per execution (request,
  result, provider, verdict, timestamp) in the incident's store.

## Persistence layer (Step 10)

`internal/store`: repository interfaces over domain protobuf types (no
`sql.Rows`, no `*sql.DB` across the boundary) → backends:

- `store`: 9 interfaces (telemetry/detection/alert append-read; incident +
  recommendation create/save/get/list; evidence/validation/response-records/
  audit append-read — audit has no update/delete surface at all) +
  in-memory implementations (fast deterministic tests) + shared `storetest`
  conformance suite every backend must pass.
- `store/sqlite`: local/lab backend. Pure-Go driver (`modernc.org/sqlite`,
  no cgo, no ORM, no migration framework). Versioned schema v1 (migrations
  in-tx, foreign keys enforced, unknown versions refused); RFC 3339 UTC
  timestamps, proto-number enums, JSON maps; every write validated first,
  every read re-validated (corruption → explicit error, digests recomputed).
  `CreateIncidentWithEvidence` proves cross-entity atomicity + rollback.
  `PersistRun` persists a validated pipeline run post-hoc (telemetry →
  evidence); poisoned input persists nothing. Empty path = `:memory:`
  (never the working tree); WAL + busy timeout + per-DSN pragmas for files.
- `store/postgres`: EXPLICIT BOUNDARY, not an implementation (Option B).
  A PG17 server runs here but no credentials are available, so nothing is
  claimed: config contract + DSN/redaction + env parsing + explicit
  `ErrPostgresUnavailable`. Gap list documented in the package. No driver
  dependency added. NOT production-ready: no HA/backup/replication/scaling.

Maturity (honest): SQLite implemented + tested (conformance, restart,
rollback, concurrency, corruption, FK, version gate). PostgreSQL:
unimplemented by environment constraint — interface-ready, runtime-absent.

## Verify

```sh
export PATH="$HOME/sdk/go/bin:$PATH"
gofmt -l .
go vet ./...
go test ./...
go test -race ./...
go build ./...
./collector --self-test   # after go build ./...
```
