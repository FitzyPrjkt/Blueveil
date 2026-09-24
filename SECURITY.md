# Security Policy

## Supported versions

Blueveil is pre-1.0 lab-grade software. Security fixes go into `main`.
There are no LTS branches.

| Version | Supported |
| ------- | --------- |
| main    | ✅        |
| anything older | ❌ |

## Reporting a vulnerability

**Do not open a public issue.** Use
[private vulnerability reporting](https://github.com/fitzyprjkt/Blueveil/security/advisories/new)
(GitHub Security Advisories).

Include:

- What you ran (binary version / commit, backend, lab vs production)
- Minimal reproduction (config + steps; synthetic data preferred)
- Impact assessment (what an attacker gains)

You will get an acknowledgment within 7 days and a fix timeline once the
issue is confirmed. Credit on request.

## Scope notes

In-scope: the collector API/auth, response safety gates, evidence integrity,
backup/restore, the Rust core, the UI's contract parsing.

Out of scope: third-party dependencies' own vulnerabilities (report those
upstream, though a Blueveil-specific exploit path is in scope), social
engineering, physical access, and deployments you misconfigured against
[`docs/OPERATOR.md`](docs/OPERATOR.md).

Known posture: [`docs/ATTACK-SURFACE.md`](docs/ATTACK-SURFACE.md) documents
the reviewed attack surface and the adversarial tests behind it.
