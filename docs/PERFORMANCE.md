# Blueveil Capacity Baseline (Step 21)

Measured on the private test host — **observed here, not universal
guarantees**:

- 2 vCPU (AMD A4-9125), ~6.9 GB RAM, local SSD, Debian 13
- Go 1.27.1, PostgreSQL 17 (private instance, unix socket + TCP),
  SQLite via modernc driver (WAL)
- Workloads: deterministic synthetic data (`internal/perf`), seeded
  lab datasets (72 telemetry / 32 detections / 23 incidents / 135
  evidence baseline), 1,000-row telemetry sets where noted

How to reproduce: `go test ./internal/perf/ -bench <Name> -benchtime
<N>x -run '^$'` (PG benches need `BLUEVEIL_TEST_POSTGRES`); mixed
soaks via the `*-soak.sh` pattern against a scratch deployment.

## API read capacity (21B)

Mixed 13-endpoint workload, 300 requests per level, SQLite + 1,000
telemetry rows:

| Concurrency | Throughput | p50 | p99 | Errors |
|---|---|---|---|---|
| 1 | ~100 rps | ~230 µs | ~50 ms | 0 |
| 10 | ~110 rps | ~230 µs | ~530 ms | 0 |
| 25–50 | ~110–120 rps | ~260–350 µs | ~1.1–1.8 s | 0 |

Throughput is flat because the mix is dominated by three full-table
routes; per-endpoint probes at concurrency 1 (100 requests each):

| Endpoint (1k rows) | p50 | Throughput |
|---|---|---|
| `/telemetry` | ~34 ms | ~29 rps |
| `/network/observations` | ~28 ms | ~34 rps |
| `/monitoring/events`, `/hunting/events` | ~18–22 ms | ~42–55 rps |
| detections, alerts, incidents, evidence, assets, GRC, supply, validation | ~60–100 µs | ~7,000–14,000 rps |

Memory backend mixed at C=10: ~205 rps (SQLite lock/IO roughly halves
it). Error paths: 200×404 burst at ~30 µs each. Gated (bcrypt
MinCost) p50 ~5.3 ms — hashing dominates handler cost; at production
DefaultCost expect ~50–100 ms per request from auth alone (kept
deliberately; see § Bottlenecks).

## Telemetry ingestion (21C)

Paced injection through the real pipeline (2,000 events, burst-capable
rules, memory stores):

| Target | Sent | Accepted | Rejected | Achieved |
|---|---|---|---|---|
| 10/s | 2000 | 2000 | 0 | 10.0/s |
| 50/s | 2000 | 2000 | 0 | 50.0/s |
| 100/s | 2000 | 2000 | 0 | 100.0/s |
| 250/s | 2000 | 2000 | 0 | 248.0/s |
| 500/s | 2000 | 2000 | 0 | 446.5/s |

No silent drops at any level (Accepted + Rejected == sent, pinned by
`TestPipelineNoSilentLoss`). The 500/s shortfall is injector pacing
(ticker + blocking send), not pipeline loss — the pipeline applies
backpressure instead of dropping.

## Detection & incident throughput (21D)

Engine with burst/stateful rules over 2,000 mixed events: ~9 µs/event
steady-state (~110k events/s single-threaded), matches counted. These
are throughput numbers, not detection-quality scores.

## PostgreSQL capacity (21E)

- Mixed reads, 1k rows, C=1: ~137 rps (faster than SQLite here —
  pool parallelism offsets per-query cost).
- Whole-run persist, 100-event batch: ~136–305 µs/event (2–4× SQLite's
  ~65 µs; network + transaction overhead).
- Pool honors `MaxConns` (verified serializing at 1); statement
  timeout kills runaway queries while the pool survives; closed-pool
  health fails explicitly.
- Backup ~0.36 s / restore ~0.37 s at 460-row lab scale (192 KB dump).

## SQLite capacity (21F)

- Mixed reads, 1k rows: ~100–120 rps flat across C=1–50 (single-writer
  lock + full-table scans); per-route profile identical in shape to PG
  but slower on heavy routes.
- Whole-run persist, 100-event batch: ~65 µs/event.
- `VACUUM INTO`: ~12 ms at 100 rows / ~18 ms at 2,000 rows; safe under
  concurrent writers (tested).
- **Cutoff observation:** SQLite is the recommended backend while the
  working set fits comfortably in one file and write concurrency stays
  modest (lab + small private use). Move to PostgreSQL when concurrent
  writers contend (busy-timeout pressure in logs), when the database
  must outlive one host's disk, or when pool/timeout controls are
  wanted. No universal row-count cutoff is claimed — it depends on
  row size and read patterns, not just count.

## Mixed workload (21G, 5 min live)

API reads + asset-ingest POSTs + readiness polls against seeded PG,
5 s sampling: zero request failures, ready throughout, RSS ~22–23 MB
flat, 8 fds, 2 PG connections, DB size static (ingest path tested
writes assets, verified growing then stable across restart in Step
18). Compared to Step 18 (18 min, ~2,700 requests, RSS 23→27 MB
settling): no new growth under the larger mixed load.

## Backup/restore performance (21H)

- SQLite `VACUUM INTO`: 12–18 ms (100–2,000 rows; snapshot 274–610 KB).
- PostgreSQL dump/restore at 460 rows: ~0.36 s / ~0.37 s.
- No compression added (integrity over speed; dumps stay greppable for
  the marker scan).

## Resource envelope (21I, observed)

| Signal | Normal (lab scale) | Note |
|---|---|---|
| RSS | 22–27 MB settling | process, seeded lab + load |
| Goroutines | ~9 steady | burst settles (tested) |
| FDs | 7–8 steady | |
| PG connections | 2 (pool, idle) | bounded by `max_conns` |
| DB size | ~9.3 MB seeded PG | grows with telemetry |
| Backup size | ~190 KB dump / ~600 KB sqlite@2k rows | |
| Queue | bounded `QueueSize`, backpressure not drops | |

Normal/warning/saturation/failure bands are **operator
recommendations, not application guarantees**: investigate sustained
RSS growth beyond ~2× baseline, fds climbing without load, or pool
saturation in logs. Blueveil itself enforces: 1 MiB bodies, 1 MiB
headers (431), `limit 1..1000`, positive shutdown bound, statement
timeouts.

## Bottlenecks (21J)

1. **Full-table protojson marshal on telemetry-family reads**
   (~20–35 ms at 1k rows, dominates mixed throughput). Not optimized:
   pagination/cursor APIs would change the API surface — recorded for
   a future step, current behavior kept.
2. **Per-request bcrypt** (~5 ms at MinCost; ~50–100 ms at production
   cost). Intentional security cost; caching verifications would trade
   security for speed — declined, documented.
3. **SQLite single-writer lock** (flat ~110 rps). By design; the PG
   backend is the answer, already shipped.
4. **PersistRunTx network round-trips** (PG ~2–4× SQLite per event).
   Normal pool/transaction cost; batching already at run granularity.

No implementation change was justified: every measured cost traces to
an intentional correctness/security property, and all envelopes sit
far above private-workstation needs.

## Untested areas

Second-peer LAN/VPN throughput, system-scope systemd under load,
cross-version upgrade timing, datasets beyond ~2k telemetry rows,
WAL pressure under sustained concurrent SQLite writers.
