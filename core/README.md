# blueveil-core (skeleton, Step 3)

Rust skeleton of the Blueveil control plane. Proves the core builds on the
contract layer with generated types only — no hand-remodelled domain, no
Redveil, no I/O.

## Build

```sh
export PROTOC="$HOME/.local/protoc-36.1/bin/protoc"
export PROTOC_INCLUDE="$HOME/.local/protoc-36.1/include"
export PATH="$HOME/.cargo/bin:$PATH"

cargo fmt --check
cargo check
cargo test
cargo clippy -- -D warnings
```

`PROTOC`/`PROTOC_INCLUDE` are required because codegen runs the real
`protoc` against `../contracts/proto` (build-time only, never linked).

## Modules (each with one minimal responsibility)

| Module | Responsibility |
|---|---|
| `contracts` | Generated types + boundary `check_*` (requiredness lives here, mirroring the JSON Schemas) |
| `domain` | Shared `CoreError` vocabulary |
| `events` | In-process fan-out bus for `TelemetryEvent` |
| `registry` | Provider register/get/list/health + `ValidationProvider` trait + `MockValidationProvider` (answers `NOT_TESTED`) |
| `policy` | `Policy` trait (`Allow`/`Deny`/`RequireApproval`) + `StaticPolicy` test double |
| `safety` | Linear state flow with approval gate on EXECUTE; `SafetyEngine::required_gate` |
| `audit` | In-memory append-only decision log (NOT tamper-proof — not claimed) |

## Dependencies (justified, minimal)

- `prost`, `prost-types`: runtime representation of the generated contracts.
- `prost-build` (build only): runs the codegen.
- `prost-reflect`, `serde_json` (dev only): parse Step-2 fixtures through the
  compiled descriptor in `tests/contract_boundary.rs`.

No web framework, ORM, broker, cloud SDK, AI, WASM, or Redveil.
