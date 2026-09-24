# Blueveil extensions (Step 11)

Polyglot vertical slices. Rule: a language ships only with a real, tested
responsibility — never scaffolding for coverage claims.

## Status

| Language | Status | Reason |
|---|---|---|
| Python | IMPLEMENTED | `python/` — deterministic IOC normalization + offline indicator matching + enrichment, stdlib only, unittest 17/17 |
| C/C++ | DEFERRED | No genuine low-level surface exists: no packets, no binary artifacts; hashing/parsing are covered by Go/Rust stdlib. FFI without a use case would violate the brief. Revisit when a binary/packet responsibility appears. |
| C# | DEFERRED | No .NET SDK and no Windows runtime in this environment — nothing could be compile-checked or executed, so any code would be unvalidated scaffolding. The contracts a future Windows collector would consume already exist and are stable (`TelemetryEvent`). Revisit on a Windows/dotNET host. |
| TypeScript | OUT OF SCOPE | UI belongs to Step 12. |

## Boundary rules (all extensions)

- Consume canonical contracts; never duplicate the domain model.
- Python speaks the JSON-Schema form of the contracts (snake_case keys,
  RFC 3339 timestamps, prefixed enum names). The `.proto` files stay the
  single source of truth; JSON Schemas are their runtime mirror.
- Data-processing only: no execution, no firewall/process/file/network
  mutation, no destructive scans. Active capabilities must go through the
  response/safety architecture.
- No network, no cloud, no external services in extensions.
- Persistence stays behind `internal/store`; extensions emit
  contract/domain objects that existing persistence consumes.
- Enrichment adds facts about observation (`blueveil.python.*`), never
  reputation scores, threat classifications, or verdicts.
