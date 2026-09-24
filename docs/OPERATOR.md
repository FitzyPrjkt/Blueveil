# Blueveil Private Operator Runbook

Blueveil is a private/self-hosted security control plane. It is **not**
published, **not** a public SaaS, and **not** certified for any
compliance regime. This runbook covers operating one instance on
infrastructure you control.

## 0. Supported private baseline

One Blueveil server (UI + API + runtime), one database, private
networking. Exactly this — no more:

- SQLite (local/lab, single node) or PostgreSQL 17 (private server)
- loopback, private LAN, or VPN/overlay exposure; TLS + bearer API
  keys + role authorization in production
- systemd user or system service; persistent database; UI + API;
  healthz (alive) + readyz (ready) endpoints

Explicitly out of scope: HA, clustering, Kubernetes, Docker
requirement, public SaaS infrastructure, load balancers, OAuth/IAM,
enterprise SSO, external SIEM/threat-intel services. Anything in that
list is a different project, not a configuration option.

### Trust boundaries and security assumptions

What Blueveil assumes (verify each for your deployment):

- **Network:** the listen address is reachable only by trusted parties
  (loopback, your LAN, or your VPN). There is no brute-force lockout;
  uniform 401s plus a private network are the defense. Never expose an
  unauthenticated lab instance beyond loopback.
- **Authentication:** bearer keys are high-entropy secrets you generate
  (`--keygen`); only bcrypt hashes are stored. Compromise response is
  rotation, not recovery — hashes in config are inert without secrets.
- **Authorization:** HTTP roles gate reachability only. Approvals and
  executions have no HTTP surface at any role; the Safety Policy inside
  the process is the only authorizer of actions.
- **TLS:** terminates at Blueveil or immediately upstream (explicit
  opt-out, logged). Certificates are yours to mint and rotate; expiry
  fails verifying clients, not startup.
- **Database:** trusted local service or socket; Blueveil authenticates
  with least-privilege credentials (CONNECT + schema CREATE, nothing
  else). Connection strings are built with proper quoting; passwords
  travel by environment, never argv or logs.
- **Backups:** database dumps contain key *hashes* but must still be
  treated as sensitive; secrets and TLS keys are never inside them
  (verified by marker scan on every backup).
- **Filesystem:** config 0640, secrets 0600, data dir owned by the
  service user. The process needs no capabilities and no root.
- **Updates:** replace binary + UI only; the database migrates forward
  transactionally; downgrades are refused, never auto-reversed.

What Blueveil does NOT promise: certification of any kind, resistance
to a compromised host or database server, or security of networks you
expose it to. It is a private instrument, not a hardened appliance.

## 1. Installation / runtime

Prerequisites:

- Go 1.27+ (collector), Rust 1.98+ with protoc 36.1 (core, optional
  unless rebuilding contracts), Python 3.13+ (IOC extension tests),
  Node 26+ (UI build), PostgreSQL 17 (only for postgres backend).
- No network access is required at runtime. Module downloads need the
  Go proxy only at build time.

Build the production artifacts (a server binary plus built UI — the
production boundary needs no source tree afterwards):

```sh
cd collector && go build -o ../dist/blueveil ./cmd/collector
cd ui && npm install && npm run build   # outputs collector/ui/dist/
```

Artifact boundary:

| Artifact | Source | Ships? |
|---|---|---|
| `dist/blueveil` | `go build -o ../dist/blueveil ./cmd/collector` (from `collector/`) | yes — the only executable |
| `collector/ui/dist/` | `npm run build` | yes — static assets only |
| `deploy/blueveil.service` | repo | yes — systemd unit template |
| `deploy/install.sh` | repo | yes — installer (not installed itself) |
| `deploy/config.example.json` | repo | yes — template only |
| `docs/OPERATOR.md` | repo | yes — this file |
| test fixtures, `*_test.go`, seed data | repo | **no** — dev-only; the binary seeds lab data only on explicit `--seed` |

Verify the boundary: build, copy the four runtime artifacts to a clean
directory, and start from there with no source checkout present
(`TestInstallFileLayoutOnly` automates the layout half of this).

### Private installation (two modes)

**A. System service (needs root once, recommended for a private host):**

```sh
sudo ./deploy/install.sh --system --backend postgres --listen 127.0.0.1:8008
# edit /etc/blueveil/config.json (backend, TLS, keys), then:
sudo systemctl daemon-reload && sudo systemctl enable --now blueveil
```

Layout: `/usr/local/bin/blueveil` (0755), `/usr/local/share/blueveil/ui`,
`/etc/blueveil/config.json` (0640 `root:blueveil`),
`/etc/blueveil/secrets.env` (0600, optional env secrets),
`/var/lib/blueveil/` (0750, database + working directory), logs via
the journal (`journalctl -u blueveil`). Runs as the dedicated `blueveil`
system user (created if absent); never as root.

**B. User install (no root):**

```sh
./deploy/install.sh --user --prefix "$HOME/blueveil" --backend sqlite
# edit ~/blueveil/etc/config.json, then:
systemctl --user daemon-reload && systemctl --user enable --now blueveil
```

Everything lands under the prefix; the unit drops mount-namespace
sandboxing (unavailable to unprivileged managers — documented in
`deploy/blueveil.service`) and keeps the namespace-free restrictions.

User services stop at logout unless lingering is enabled (a real
operational gotcha — not a Blueveil bug):

```sh
loginctl enable-linger "$USER"   # keep user services running after logout
```

Verify with: log out, log back in, `systemctl --user is-active blueveil`.

The installer never overwrites `config.json`, validates the unit with
`systemd-analyze verify`, and only reports success after `readyz`
reports `ready`. Installer flags: `--system` | `--user --prefix DIR`
(required mode), `--backend sqlite|postgres`, `--listen ADDR`,
`--bin PATH` (server artifact, default `<repo>/dist/blueveil`),
`--ui-dir PATH` (built UI, default `<repo>/collector/ui/dist`),
`--no-start` (install files only, for review before first start).

### Service lifecycle

```sh
systemctl [--user] status blueveil     # state + recent logs
systemctl [--user] stop blueveil       # graceful SIGTERM: drain → close → exit
systemctl [--user] restart blueveil    # stop + start (state preserved)
systemctl [--user] disable --now blueveil
journalctl -u blueveil --no-pager      # logs (add --user for user scope)
```

Crash loops are bounded (`StartLimitBurst=3` per 5 min, then failed
state for the operator). Deterministic config failures (exit 2) never
restart-loop (`RestartPreventExitStatus=2`).

### Upgrade (safe sequence)

1. `systemctl [--user] stop blueveil`
2. Replace the binary and UI only (`bin/blueveil`, `share/ui`).
   Never touch `config.json`, `secrets.env`, or the database.
3. `systemctl [--user] start blueveil` — migrations run forward-only
   inside one transaction at open.
4. Poll `readyz` until `ready`; check version-specific notes below.

Rules: persisted data always survives (verified by restart tests);
a failed migration leaves the old schema untouched and the process
refuses to start (fix config/DB, do not hand-edit rows); downgrades
are refused (a newer `schema_version` will not open); old config files
keep working (new fields take safe defaults — pinned by
`TestOldConfigFileUpgradesCleanly`); if an upgrade fails, the previous
binary + untouched database restart exactly as before.

### Health verification (authoritative order)

```sh
systemctl [--user] is-active blueveil            # process supervision only
curl -sf http://127.0.0.1:8008/api/v1/healthz   # process alive?
curl -sf http://127.0.0.1:8008/api/v1/readyz    # READY? (database + schema)
curl -sf -H "Authorization: Bearer $KEY" \
  http://127.0.0.1:8008/api/v1/assets | head -c 200   # authenticated read
# UI: open http(s)://<addr>/ — unlock panel appears iff auth is on.
```

Never report success from process existence alone: `active` +
`healthz 200` + `readyz {"status":"ready"}` is the triple. During a DB
outage the triple reads `active` / 200 / 503 `not-ready` — that split
is the design, not a bug.

### PostgreSQL private setup

```sql
CREATE ROLE blueveil LOGIN PASSWORD '...';   -- or peer auth over socket
CREATE DATABASE blueveil OWNER blueveil;
-- inside blueveil as the role's admin session:
GRANT CONNECT ON DATABASE blueveil TO blueveil;
GRANT CREATE ON SCHEMA public TO blueveil;   -- migrations create tables
```

The role needs nothing else: no superuser, no `CREATEDB` (verified by
`TestLiveLeastPrivilegeRole`, which also proves the role cannot create
databases). Connection: host/port/user/dbname + `sslmode=require`
minimum over TCP (unix socket may use peer auth without a password).
Externally managed PostgreSQL works the same way — the unit only
*orders after* a local `postgresql.service` without requiring it.

### Starting by hand (lab; `blueveil` = your built `dist/blueveil`)

```sh
blueveil --seed --db /var/lib/blueveil/lab.db
blueveil --serve --db /var/lib/blueveil/lab.db --addr 127.0.0.1:8008
```

Stopping: `SIGINT`/`SIGTERM` (Ctrl-C, `kill`, `systemctl stop`).
Shutdown is graceful and bounded (default 10s, `limits.shutdown_timeout`):
in-flight requests drain, then persistence handles close. A second
signal never corrupts state; the process always exits exactly once.

## 2. Configuration

Single model: `collector/internal/config`. Precedence (lowest first):
compiled lab defaults < JSON file (`--config` / `BLUEVEIL_CONFIG_FILE`)
< `BLUEVEIL_*` environment < CLI flags (operational surface only).

Secrets travel by file or environment **only**, never by flag
(command lines leak via `ps`):

- `BLUEVEIL_PG_PASSWORD` — database password
- `BLUEVEIL_API_KEYS` — JSON array of `{id, role, hash, expires_at?}`
- `BLUEVEIL_CONFIG_FILE` — full JSON config (0600 recommended)

Key fields:

| Setting | Purpose | Default (lab) | Production rule |
|---|---|---|---|
| `env` | lab \| production | lab | explicit |
| `listen_addr` | bind address | 127.0.0.1:8008 | any; lab refuses non-loopback |
| `database.backend` | sqlite \| postgres | sqlite | explicit path / full PG settings |
| `database.postgres.*` | host/port/user/dbname/sslmode/max_conns/timeouts | 127.0.0.1:5432, require | TCP needs password + sslmode ≥ require; unix socket may use peer auth |
| `tls.enabled/cert_file/key_file/min_version` | transport | off / 1.3 | on, or explicit `explicit_insecure_http` (TLS terminated upstream) |
| `auth.enabled/keys` | bearer API keys (bcrypt hashes) | off | on, ≥1 key, unique ids, known roles |
| `logging.level/format` | debug\|info\|warn\|error, text\|json | info/text | json recommended |
| `limits.request_body_bytes` | max request payload | 1 MiB | excess → 400, never buffered unbounded |
| `limits.read_header_timeout` | slow-header bound | 5s | anti-slowloris |
| `limits.shutdown_timeout` | drain bound on SIGTERM | 10s | stuck handlers are cut off, then exit |
| `database.postgres.query_timeout` | per-query bound | unset | slow queries die, pool stays usable |

Validation runs before any side effect (DB open, listener bind).
Errors name fields and rules, never secret values.

## 3. Database

SQLite (local/lab, single node):

- File at `database.sqlite_path`. WAL mode + `busy_timeout(5000)` +
  foreign keys are enforced at open; a database that cannot do WAL is
  refused rather than silently downgraded.
- `:memory:` is refused in production.

PostgreSQL (private/self-hosted):

- Needs an existing empty database + a role that can create tables.
  Example (private host, peer or password auth per your policy):
  `CREATE DATABASE blueveil; CREATE USER blueveil ...;`
- `sslmode=require` minimum over TCP in production.
- Pool: `max_conns` (default 8, verified serializing at 1),
  `connect_timeout`, per-connection `query_timeout`
  (`statement_timeout`; slow queries error, pool survives).
- Reconnect is pool-automatic; a closed pool (process shutdown) fails
  explicitly — recovery means the process re-opens on (re)start.

Migrations (both backends, v1→v5 lineage):

- Apply forward-only inside one transaction at open; a failed step
  rolls back fully — no partial schema is ever accepted.
- Future or unknown schema versions refuse to open.
- No destructive automatic migration exists. No migration framework.

Readiness:

- `GET /api/v1/healthz` — process alive (always 200 when serving).
- `GET /api/v1/readyz` — `ready` only when serving AND the configured
  database answers with a supported schema; otherwise 503 `not-ready`
  with per-check detail. During shutdown drain, readyz flips first.

Corruption behavior: a tampered row fails the owning route with
`INTEGRITY_FAILURE` (HTTP 500), never an empty list; other routes keep
serving. Repair means fixing the row out-of-band, then reads resume.

## 4. Authentication

Bearer API keys (`Authorization: Bearer <secret>`). Only bcrypt hashes
are stored — in the config file or `BLUEVEIL_API_KEYS`, never the
secret, never in logs.

Creating a key (secret via stdin — never argv, which leaks via `ps`):

```sh
printf '%s' 'my-secret-value' | blueveil --keygen --key-id analyst-alice --key-role READ
# {"id": "analyst-alice", "role": "READ", "hash": "$2a$10$..."}
```

Paste the fragment into `auth.keys`. Suggested IDs are stable labels
(`ingest-01`, `analyst-alice`); roles are `READ < RESPOND < VALIDATE <
ADMIN` (higher includes lower).

- Rotation: configure old + new IDs together (both accepted), switch
  clients, remove the old ID, restart (or reload). Revoked IDs fail
  closed with 401.
- Expiration: `expires_at` (RFC3339) fails closed at startup if past,
  and at request time with `credential expired` once crossed.
- Locking the UI: the workstation shows an unlock panel on 401. Keys
  live in session storage only; **Forget key** clears and reloads.
  A rotated/revoked key surfaces as “stored key was rejected”.
- There is deliberately **no brute-force lockout**: failed attempts
  return uniform 401s with no id-oracle. Operate the API behind your
  private network (Section 6) and rotate on suspicion.

## 5. Authorization

Roles form one hierarchy: `READ < RESPOND < VALIDATE < ADMIN`.
Every `/api/` route needs an authenticated role except health/readyz:

| Operation | Required |
|---|---|
| all GET routes | READ (or higher) |
| `POST /api/v1/assets/observations` | RESPOND (or higher) |
| `PATCH /api/v1/assets/{id}/lifecycle` | ADMIN |
| unknown `/api/` paths | fail closed (401 anon / 404 authed) |

HTTP roles gate reachability only. They never approve, execute, or
bypass the response Safety Policy: approvals/executions have **no**
HTTP write surface (`405` for every role, including ADMIN).

## 6. Private networking

| Bind | Meaning | When |
|---|---|---|
| `127.0.0.1` / `localhost` / `::1` | this host only | lab default; required in lab (non-loopback is a startup error) |
| LAN address (e.g. `192.168.x.x`) | your private network | trusted LAN + production auth + TLS |
| VPN/overlay (e.g. Tailscale IP) | your private overlay | recommended for remote private use; Tailscale itself is optional, never a dependency |
| `0.0.0.0` / public interface | reachable per host firewall/routing | only behind TLS you control, with auth on; **never** expose an unauthenticated lab configuration to an untrusted network |

No reverse proxy is required. If you terminate TLS upstream, set
`tls.explicit_insecure_http` deliberately (it is logged as a warning).

Verify what actually listens (do this after every install):

```sh
ss -tlnp | grep blueveil          # expect exactly your listen_addr
curl -sf http://127.0.0.1:PORT/api/v1/healthz
# from another LAN host (only if you bound one):
curl -sf http://<lan-ip>:PORT/api/v1/healthz   # 200: reachable AND still gated
curl -s http://<lan-ip>:PORT/api/v1/assets     # must be 401 without a key
```

Tailscale/VPN: bind the VPN IP (or keep loopback and access over
`tailscale serve`/ssh forwarding). Tailscale is never required and
nothing in Blueveil depends on it. A public interface bind is
supported only with TLS + auth on, and even then prefer a VPN.

## 7. Troubleshooting

| Symptom | Meaning | Check |
|---|---|---|
| `config: lab listen_addr must be loopback` | lab would be network-exposed | bind loopback or set `env: production` with auth+TLS |
| service `failed`, exit 2, no restarts | deterministic config error | `journalctl -u blueveil`; fix config (see message); `RestartPreventExitStatus` intentionally does not loop |
| service restarts ≤3 then stays failed | crash loop | `journalctl -u blueveil`; fix cause; `systemctl reset-failed` + start |
| `readyz not-ready` while `healthz` 200 | dependency down (usually DB) | database process/credentials/`schema_version`; readiness ≠ liveness |
| install reports “never became ready” | service started but dependencies unmet | same as above; also confirm the configured port is free |
| `config: production requires auth.enabled` | prod without credentials | add keys |
| `serve: tls cert/key failed to load` | bad paths/permissions/mismatch | files readable? pair matches? (`tls.explicit_insecure_http` only if TLS ends upstream) |
| `401 UNAUTHORIZED` | missing/invalid/expired key | unlock panel; `credential expired` means rotate; rejected stored key means rotation completed server-side |
| `403 FORBIDDEN` | role too low | key role vs Section 5 table |
| `readyz: not-ready`, `database: unreachable` | DB down/unmigrated | process, credentials, `schema_version`, server logs |
| `migration failure` | schema refused | version mismatch (future/unknown) — inspect `schema_version`, never hand-edit rows |
| `INTEGRITY_FAILURE` on one route | tampered row | scope is the named route only; repair the row; other routes unaffected |
| `405 METHOD_NOT_ALLOWED` | wrong method (or a write API that does not exist) | use the documented method; approvals/execution are never HTTP-writable |

Logs (`logging.format=json` recommended) carry timestamp, level,
component, operation, request ID, role, status, duration — never
credentials, headers, bodies, or keys. Request IDs also ride the
`X-Request-ID` response header: quote it in bug reports.

## 8. Backup, restore, recovery

Backup and restore are implemented (`--backup`, `--restore`,
`--prune-backups`); there is still no schedule, no replication, no
off-host automation — those remain operator procedures below.

### Backup

Prerequisites: a valid config file; for PostgreSQL, `pg_dump`/`psql`
client tools installed. The source schema must already be current
(start the server once to migrate — backup refuses anything else and
never migrates as a side effect).

```sh
blueveil --backup --config /etc/blueveil/config.json --backup-out /var/backups/blueveil
# backup /var/backups/blueveil/backup-20260919T024733Z-postgres backend=postgres schema=5 tables=26
# backup PASS
```

What it does: PostgreSQL → native `pg_dump --no-owner
--no-privileges` (one database only, password by environment, never
argv); SQLite → online `VACUUM INTO` snapshot (consistent under
writers, no stop required, no WAL file surgery). Then: table counts
into `backup.json`, SHA-256 per payload file, secret-marker scan
(private keys, connection passwords, test markers, secret-valued
keys). Any failure removes the partial output and exits non-zero —
a failed backup never looks valid.

Verify (a backup is valid only if the restore below succeeds, but the
cheap checks come first):

```sh
ls /var/backups/blueveil/backup-*/backup.json
grep -riE "PRIVATE KEY|password=" /var/backups/blueveil/<name>/dump.sql || echo "no markers"
```

### Restore

```sh
# PostgreSQL into an isolated database (never the live one first):
blueveil --restore --config /etc/blueveil/config.json \
  --restore-from /var/backups/blueveil/<name> --restore-dbname blueveil_restore_test
# restore verified: 26 tables, 460 rows
# restore PASS
```

Rules enforced by the tool (not just documented):

- manifest parsed + every payload hash/size re-verified (tampered or
  truncated archives fail before anything is touched);
- backend must match config (no sqlite↔postgres reinterpretation);
- target must be absent or empty, otherwise refusal without `--force`
  (`--force` drops + recreates explicitly — the destructive choice);
- native restore with stop-on-first-error, then the restored database
  is opened (older schemas migrate forward, newer refuse) and every
  manifest count is reproduced exactly, or the restore fails;
- failed restores leave the target in place for investigation and say
  so; the backup directory is never written to.

SQLite restores to the configured path (`--restore-dbname` is refused
as meaningless there); the same empty-or-`--force` rule applies.
After restore, start the server against the restored target and walk
the health checklist from §"Health verification": readyz `ready`,
authenticated read, representative rows, evidence digests
(`sha256(content)` recomputed — the API serves both fields),
audit trail intact.

### Recovery

| Failure | Do |
|---|---|
| database unavailable | readyz goes `not-ready`, routes fail bounded; fix DB/connectivity, process recovers without restart (pool reconnects) |
| backup fails | read the bounded error; partial output is already removed; fix cause (DB down, bad destination, ancient schema) and re-run — never hand-edit a partial directory into shape |
| restore fails | read the error; target left in place — inspect, drop it, fix cause (conflicting target → new name or `--force`; corrupt archive → discard the archive, never the source DB) |
| database corrupted | scope is per-row: owning route reports `INTEGRITY_FAILURE`, rest serves; never auto-repair evidence; repair the row out-of-band or restore into a clean target |
| schema unsupported | binary refuses to open; restore/upgrade to a matching version; never hand-edit `schema_version` |
| TLS material lost | replace cert/key files, restart; no data impact |
| API keys lost | generate new ones (`--keygen`), update config, restart; old hashes in config are inert without their secrets |
| configuration lost | rebuild from the runbook §2 table + secrets out-of-band; the database holds no secrets to recover them from |

Recoverable application state: the whole database. Separately kept:
config/secrets (versioned access-controlled, out-of-band), TLS keys
(host custody), UI/binary (rebuildable artifacts). Irreplaceable:
evidence content + digests and the audit trail — which is exactly why
restores are count- and digest-verified rather than trusted.

### Retention

Naming: `backup-<UTC-basic-timestamp>-<backend>` (sortable, parseable).
Record per backup: timestamp, database identity, schema version, table
counts (all in `backup.json`). Recommendation (not a guarantee):
daily, keep 7, restore-test monthly — via explicit
`blueveil --prune-backups --prune-dir DIR --keep N` (refuses N<1, never
touches non-backup entries, reports removals). Encryption at rest and
off-host copies are the operator's responsibility using host tooling;
database backups contain key *hashes* only, but treat archives as
sensitive regardless. Failed backups are removed, never retained.

### Pre-backup architecture review (boundary for future work)

Persisted state (needs backup): the whole database — telemetry,
detections, alerts, incidents, evidence **with digests**, response
records + audit, validation results/campaigns/exercises, asset
inventory + relationships, GRC assessments/resilience, supply-chain
entities — i.e. a consistent whole-DB snapshot; per-table copies can
violate foreign keys.

NOT database state (do not expect it in a DB backup):

- `config.json` / environment (binds, TLS paths, keys) — version
  separately, access-controlled.
- API key **secrets** (only hashes live in config) — distribute
  out-of-band, never alongside backups.
- TLS private keys — host key material, separate custody.

Must never be backed up in plaintext:

- API key secrets, database passwords, TLS private keys. A database
  backup contains only hashes; keep it that way — verify restores
  contain no `password`/`secret` plaintext before trusting the pipeline.

Integrity fields that make restores verifiable later: evidence
`sha256` digests (re-verify after restore), deterministic IDs
(regenerate-and-compare), `schema_version` (refuse to serve a restore
the code does not speak).

Consistency rules for whoever builds this later:

- SQLite uses WAL: copy the database file only while the service is
  **stopped** (or checkpoint + copy both `db` and `db-wal`
  atomically). A live copy of the main file alone is not a backup.
- PostgreSQL: snapshot the whole database in one transaction
  (`pg_dump` default behavior); per-table copies can violate foreign
  keys on restore.
- Verified pre-backup property (Step 18 audit): a full dump contains
  zero secret markers and only key *hashes* — re-run that scan against
  any future backup pipeline before trusting it.
