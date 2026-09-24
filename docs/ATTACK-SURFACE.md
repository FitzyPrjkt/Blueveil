# Blueveil Attack-Surface Inventory (Step 20A)

Implementation-oriented map for adversarial testing. Every boundary
lists input, trust level, validation, authorization, failure behavior,
data written, secret exposure, and the tests that pin it. Threats
assume the supported private baseline (OPERATOR.md §0) — loopback/LAN/
VPN, authenticated production — never public SaaS architecture.

Conventions: trust levels are U (untrusted/network), O (operator
config, trusted but validated), I (internal/caller code).

## HTTP/API (`collector/internal/api`)

| # | Boundary | Input | Trust | Validation | AuthZ | Failure | Writes | Secrets | Tests |
|---|---|---|---|---|---|---|---|---|---|
| H1 | route mux + middleware | method, path, headers, query, body | U | allowlist routes; bounded enums; `limit 1..1000` | gate before handlers; unknown `/api/` fail-closed | 400/404/405/500 envelope, never empty-on-error | none on GET; 2 ingest paths only | never logged/echoed (obs redaction + gate tests) | `api_boundary_test.go`, `authz_matrix_test.go`, `middleware_test.go` |
| H1b | dot-segment paths | `/..`, `/.`, encoded dots | U | TWO layers: Go server/mux pre-cleans and 307-redirects to canonical form; the gate additionally rejects uncleaned forms (unit tests invoke handlers directly, bypassing server cleaning, and assert 401) | every redirect target re-enters the gate (verified live: dirty→public gives public content only; dirty→protected gives 401/404) | none | n/a | `authz_matrix_test.go` (strict), live redirect-chain probes (Step 23) |
| H2 | path IDs | `{id}` segments | U | non-empty, no `/`; existence via store | READ+ | 400/404 | none | none | boundary suite |
| H3 | query filters | enums, limits, timestamps | U | per-filter vocabularies; `limit 1..1000`; RFC3339 times | READ+ | 400 | none | filters never logged (path-only access logs) | boundary suite |
| H4 | POST/PATCH bodies | JSON observation/lifecycle | U | strict shape + contract validation | RESPOND / ADMIN | 400/403/404 | assets only | bodies never logged | boundary + matrix |
| H5 | error responses | — | — | fixed `{error:{code,message}}` codes | n/a | codes UNAUTHORIZED/FORBIDDEN/BAD_REQUEST/NOT_FOUND/METHOD_NOT_ALLOWED/INTERNAL/INTEGRITY_FAILURE | none | no traces, no values | envelope tests |

## Authentication (`internal/auth`, gate in `internal/api/middleware.go`)

| # | Boundary | Input | Trust | Validation | Failure | Secrets | Tests |
|---|---|---|---|---|---|---|---|
| A1 | `Authorization: Bearer` parse | header value | U | exact scheme, non-empty secret | 401 bounded (missing/invalid/expired) | header never logged/stored | `auth_test.go`, gate tests |
| A2 | verifier compare | secret vs N bcrypt hashes | U | all verifiers tried uniformly | 401 uniform, no id oracle | hashes config-side only; secret never persisted | rotation/expiry/no-leak tests |
| A3 | key configuration | id/role/hash/expiry | O | validated at construction + config validation | startup refusal | hashes only (bcrypt) | construction + config tests |
| A4 | UI key handling | password input | U | sessionStorage only | 401 → unlock panel | never localStorage/URL/logs | `api.test.ts`, `authlock.test.tsx` |

## TLS (`cmd/collector/serve.go`, `internal/config`)

| # | Boundary | Input | Trust | Validation | Failure | Tests |
|---|---|---|---|---|---|---|
| T1 | cert/key files | PEM paths | O | `LoadX509KeyPair` at startup (missing/mismatch fail) | startup refusal | `serve15_test.go` |
| T2 | min version | `1.2`/`1.3` | O | allowlist, default 1.3 | startup refusal | config + serve tests |
| T3 | handshake | client TLS | U | Go TLS stack, no custom crypto | handshake failure, plaintext refused | runtime smoke (Step 16/18) |

## Configuration & CLI (`internal/config`, `cmd/collector`)

| # | Boundary | Input | Trust | Validation | Failure | Secrets | Tests |
|---|---|---|---|---|---|---|---|
| C1 | env/file/flags | `BLUEVEIL_*`, JSON, argv | O | typed validation before side effects; secrets never echoed | exit 2, actionable message | `Redacted()` view; no secret flags | `config_test.go`, serve tests |
| C2 | listen address | host:port | O | parse + lab-loopback refusal | startup refusal | n/a | bind tests |
| C3 | CLI bodies (`--backup-out`, `--restore-from`, unit paths) | paths | O | existence/shape checks at use | explicit errors | n/a | backup + install tests |
| C4 | `--keygen` (secret via stdin only) | secret bytes | U | non-empty, valid role; hash-only output | exit 2/1 bounded | never argv/output/logs | keygen tests |
| C5 | `--version` | none | — | none (read-only build info) | n/a | no inputs, no secrets | version test |

## Backup/restore/prune (`internal/backup`)

| # | Boundary | Input | Trust | Validation | Failure | Writes | Secrets | Tests |
|---|---|---|---|---|---|---|---|---|
| B1 | backup source | config DB pointer | O | schema must be current (read-only check) | explicit refusal, partial removed | new timestamped dir only | marker scan before accept | live + unit tests |
| B2 | manifest | `backup.json` | U (archive may travel) | strict JSON, format v1, hash/size per file | refusal, nothing touched | none (read path) | markers scanned | manifest/tamper tests |
| B3 | payload | `dump.sql` / `blueveil.db` | U | hash/size gate, then native-tool + count verification | refusal, target left for investigation | isolated target only | scanned pre-accept | tamper/truncate tests |
| B4 | restore target | dbname/path + `--force` | O | absent-or-empty required; force drops explicitly | refusal | target only, never backup dir | n/a | conflict/force tests |
| B5 | prune | dir + keep N | O | N≥1, only `backup-*` dirs | refusal | deletions reported | n/a | prune tests |

## SQLite (`internal/store/sqlite`)

| # | Boundary | Input | Trust | Validation | Failure | Tests |
|---|---|---|---|---|---|---|
| S1 | file path / DSN | operator path | O | WAL/FK/busy-timeout enforced at open | open refusal | open tests |
| S2 | stored rows | all columns | I+disk | contract re-validation + canonical check on every read | `ErrCorrupted`, never empty | corruption matrix (Step 14) |
| S3 | migrations v1–v5 | version row | disk | single-tx apply; future/unknown refused | open refusal, nothing half-applied | migration tests |
| S4 | `VACUUM INTO` dest | derived path | — | fixed filename under backup dir | explicit error | backup tests |

## PostgreSQL (`internal/store/postgres`)

| # | Boundary | Input | Trust | Validation | Failure | Tests |
|---|---|---|---|---|---|---|
| P1 | connection params | host/port/user/db/ssl | O | typed validation; password env-only | startup refusal, no secret echo | config + serve tests |
| P2 | stored rows | all columns/tables | I+disk | same re-validation as SQLite | `ErrCorrupted` | live parity + corruption tests |
| P3 | migrations | version row | disk | single-tx; future/unknown refused; rollback-tested | open refusal | live migration tests |
| P4 | pool | concurrent queries | I | MaxConns, statement timeout, health | bounded errors, pool survives | timeout/pool/close tests |
| P5 | native tools | pg_dump/psql lookup + args | O | PATH + Debian bindir lookup; password by env | explicit error | live backup/restore tests |

## Persistence/repository boundaries (`internal/store`, domain `Validate`)

All repositories accept domain/protobuf types only (no SQL/db types
cross the boundary), validate before write (`ErrInvalid`), map
collisions (`ErrDuplicate`) and absence (`ErrNotFound`) explicitly.
Covered by: store conformance, corruption matrices, concurrency tests.

## Protobuf/JSON boundaries (`internal/contract`, `contracts/`)

Required fields, explicit enums (never UNSPECIFIED), timestamp
presence + range (`requireTimestamp`), confidence NaN/range,
lowercase-hex digests. Covered by: contract unit tests, Rust
`contract_boundary.rs` fixtures, UI parser tests.

## Telemetry ingestion & detection (`source` → `pipeline` → `detect`)

Raw events → contract validation → redaction sinks → correlation →
rules with explicit operator severity → incidents → evidence (digest).
Rule errors abort loudly (never silent clearing); duplicate IDs are
caller errors. Covered by: pipeline/detect/enrich/normalize/source
suites, redaction tests, seed redaction gate.

## Evidence & audit

Content-addressed (`SHA-256(content)`, verified on every read),
append-only audit (no update/delete surface), tamper fails closed.
Covered by: evidence tests, audit tests, corruption matrices,
integrity invariants, restore digest re-verification.

## Validation providers

`ValidationExecutor` single-invocation guarantee; provider errors stay
errors (never verdicts); `NOT_TESTED` never passes; scripted-provider
verdicts fail fast. Covered by: runner/flow/native tests, counting
provider test.

## UI (`collector/ui`)

Parsers bound every backend enum; `invalid` vs `backend-error` vs
`empty` never collapse; envelope-gated evidence badge; key in
sessionStorage only, Bearer header only, 401 → unlock panel.
Covered by: parser tests, view tests, api/authlock tests.

## Systemd packaging (`deploy/`)

Unit template (absolute paths baked at install), user flavor without
mount-namespace directives, `RestartPreventExitStatus=2` (config
errors never loop), crash-loop bound, secrets only via 0600
`secrets.env` (never `Environment=`). Covered by: sandbox-content
test, layout test, clean-install test (user systemd, live).

## Filesystem permissions

Binary 0755; config 0640; secrets 0600; data dir 0750; UI assets
read-only. Covered by: install layout tests. Working directory is the
only writable path for the system unit.

## Environment variables

Only `BLUEVEIL_*` is read, in exactly one place (`internal/config`).
Secrets accepted: `BLUEVEIL_PG_PASSWORD`, `BLUEVEIL_API_KEYS`.
Covered by: centralized-parsing test, redaction tests.

## Logs/observability (`internal/obs`, API middleware)

slog text/JSON with record-level secret redaction; request IDs
propagated; access logs carry path (never query), status, role —
never headers/bodies/credentials. Metrics count real events only.
Covered by: obs tests, access-log tests, error-ID tests.

## Shutdown/restart

Signal → readiness flip → drain bounded by `shutdown_timeout` →
persistence close exactly once → exit; repeats safe. Covered by:
lifecycle tests (drain, bound, repeats), live SIGTERM matrix.
