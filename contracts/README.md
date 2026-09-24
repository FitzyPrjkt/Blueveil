# Blueveil Contract Layer (v1)

Language-neutral boundary for the Blueveil control plane. Canonical definitions
are the `.proto` files under `proto/`; the JSON Schemas under `jsonschema/`
express the **same** contracts for runtime validation; `fixtures/` proves both.

Status: IMPLEMENTED. The Rust core (`core/`), Go collector (`collector/`
with detection engine, SQLite persistence, API, UI, and providers), and
polyglot extensions (`extensions/`) all implement these contracts. The
JSON Schemas, Rust `check_*`, and Go `Validate*` are three hand-maintained
views of the same boundary: known proto3 leniencies (absent enums read as
`UNSPECIFIED`/0, absent `approval_required` reads as `false`) are accepted
by code but rejected by schema, and each side pins its divergences in
tests (`core/tests/contract_boundary.rs`,
`collector/internal/contract/*_test.go`).

## Layout

```
contracts/
├── proto/blueveil/contracts/v1/   canonical definitions (package blueveil.contracts.v1)
├── jsonschema/                    same contracts as Draft 2020-12 JSON Schema
├── fixtures/<contract>/{valid,invalid}.json (+ validation extra cases)
└── README.md                      this file
```

Step 8 added `response.proto` (ResponseRecommendation, ResponseApproval,
ResponseExecution, ResponseVerification + OperationType, RiskLevel,
ResponseStatus, VerificationOutcome) alongside — not instead of — the
existing messages. No existing message, field number, enum, or required set
was touched: purely additive, v1-compatible. Deliberately absent from the
new enums: SUCCESS, SECURE, PASS — outcomes stay explicit.

## Versioning decision

- Contract package is `blueveil.contracts.v1`. Additive changes (new optional
  field, new enum value) stay in `v1`. Any breaking change (renamed/removed
  field, renumbered field, changed semantics) requires a new `v2` package that
  coexists with `v1` — never a silent in-place break.
- Removed fields are `reserved` by number and name in the `.proto` so numbers
  are never reused.
- `ValidationResult.contract_version` (pattern `^blueveil\.contracts\.v[0-9]+$`)
  records which contract version a provider speaks, so core can detect
  version skew at runtime.
- No other versioning machinery exists yet (no registry, no negotiation) —
  that arrives with the provider contracts, not speculatively here.

## Proto ↔ JSON mapping (documented, enforced by check)

| Aspect | Proto | JSON Schema | Rule |
|---|---|---|---|
| Field names | `snake_case` fields with explicit `json_name` | identical `snake_case` keys | Canonical JSON uses original field names, which proto-JSON parsers accept. camelCase MUST NOT be produced. |
| Enums | `PREFIXED_NAME = N`, zero = `*_UNSPECIFIED` | enum arrays of the same names **excluding** `*_UNSPECIFIED` | A missing/defaulted enum fails validation. No numeric enums in JSON. |
| Timestamps | `google.protobuf.Timestamp` | `{"type":"string","format":"date-time"}` (RFC 3339) | Validators MUST enable format assertion. |
| `map<string,string>` | `attributes`, `context` | object with `additionalProperties: {type string}` | Keys/values are strings only. |
| `repeated` | lists | arrays; `minItems: 1` where non-empty is required (event/detection/alert id lists) | proto3 cannot express cardinality — the schema is authoritative. |
| `required` | proto3 has no required fields | `required` arrays per schema | Requiredness lives in the schema + core validation, never assumed from proto. |
| `double confidence` | unbounded | `minimum: 0.0, maximum: 1.0` | Range lives in the schema. |
| `sha256` | plain string | `pattern: ^[0-9a-f]{64}$` when present | Pattern lives in the schema. |
| Unknown fields | — | `additionalProperties: false` everywhere | Strict v1: additive evolution requires a lockstep schema update (see versioning). |
| Binary data | `raw: string` is UTF-8 text | same | Binary is out of scope for v1; producers base64-encode and declare it in `attributes`. |

## Deliberate omissions (not oversights)

- **Response model is read-side + simulated execution only**
  (`proto/.../response.proto`, `response_*.schema.json`). Recommendations,
  approvals, executions, and verifications are recorded; the only executors
  are simulated. No real blocking, isolation, deletion, or mutation.
- **No `SECURE`/pass verdict.** `NOT_TESTED` means no validation was performed
  and must never be rendered as secure. `UNKNOWN` means validation ran without
  a determinate outcome. They are different states.
- **No `SECURE`/pass verdict.** `NOT_TESTED` means no validation was performed
  and must never be rendered as secure. `UNKNOWN` means validation ran without
  a determinate outcome. They are different states.
- **No provider registry, no source registry, no object storage.**
  `provider`/`source` are free strings until their registry contracts exist.
- **String-ID references** (`asset_id`, `incident_id`, …) instead of nested
  messages, so entities evolve independently.

## Fixtures

All fixtures are synthetic contract test data, marked as such inside the
payload. They are NOT real security findings. Each `invalid.*` fails for
exactly one reason:

| Fixture | Expected failure |
|---|---|
| `asset/invalid.json` | missing required `type` |
| `asset/valid_full.json` | VALID — Step-13A fields (status, timestamps, environment) |
| `asset/invalid_status.json` | explicit `*_UNSPECIFIED` status rejected |
| `identity/invalid.json` | unknown enum `IDENTITY_TYPE_ROOT` |
| `telemetry/invalid.json` | missing required `severity` |
| `detection/invalid.json` | empty `telemetry_event_ids` (`minItems: 1`) |
| `alert/invalid.json` | unknown enum `ALERT_STATUS_SNOOZED` |
| `incident/invalid.json` | `created_at` not RFC 3339 |
| `evidence/invalid.json` | `sha256` violates hex-64 pattern |
| `validation/invalid_request.json` | missing required `control_id` |
| `validation/invalid_result.json` | missing required `verdict` |
| `validation/valid_result_not_tested.json` | VALID — proves `NOT_TESTED` exists and is distinct from any pass state |
| `response/invalid_recommendation.json` | missing required `operation` |
| `response/invalid_approval.json` | `expires_at` not RFC 3339 |
| `response/invalid_execution.json` | missing required `detail` |
| `response/invalid_verification.json` | `verified_at` not RFC 3339 |
| `response/valid_verification.json` | VALID — proves `UNKNOWN` exists and is distinct from verified |

## Verification (reproducible)

```bash
export PATH="$HOME/.local/protoc-36.1/bin:$PATH"
P=/workspace/projects/Blueveil/contracts
protoc -I$P/proto -I$HOME/.local/protoc-36.1/include \
  --descriptor_set_out=/tmp/blueveil_contracts.pb --include_imports \
  $(find $P/proto -name '*.proto')
# validate fixtures against schemas (see /tmp check script used at authoring time)
```

Redveil boundary: nothing under `/workspace/projects/Redveil` was read, copied
or imported while authoring these contracts. The word "redveil" appears in
prose only (this file, as a future-provider example), never as a dependency.
