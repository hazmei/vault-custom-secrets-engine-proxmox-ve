# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

@AGENTS.md

## Commands

```bash
go build ./...
make build                               # builds plugin into vault/plugins/
make test                                # unit tests (mocked Proxmox client)
go test ./... -run TestXxx -v              # single test
make testacc                              # operator-run acceptance tests (needs disposable/dev Proxmox)
make lint                                # pinned golangci-lint + shellcheck scripts/*.sh
make verify-artifact                      # operator-run artifact/permission verification
```

CI also runs the `verify-plugin-artifact` smoke test against valid and invalid
artifact-verification inputs.

Current phase validation status, including the recorded PVE build, optional
acceptance-test skip gates, and unverified production catalog registration, is
tracked in `docs/IMPLEMENTATION_PLAN.md`.

Recorded validation (2026-08-20) against disposable PVE
`pve-manager/9.2.10/43df2e01f27a1a19` includes a successful `make build`, Vault
`server -dev` plugin auto-registration with
`-dev-plugin-dir=./vault/plugins`, engine enablement, and the full real-Vault
issue/use/renew/revoke lifecycle. The required positive authorization canary
also passed. Production-style catalog registration with
`vault plugin register -sha256=<hash>` remains unverified. Do not describe the
project as production-ready. Optional insufficient-privilege, direct-ACL, and
negative-authorization canaries may be skipped only when their documented
prerequisites are unset, and such skips are not completed tests.

The Phase 2 deferred review backlog (DR-1 … DR-6) is fully resolved; no deferred
review items remain. This does NOT change the production-readiness position
above — unverified production catalog registration and the optional canary skip
gates are independent of that backlog.

## Constraints beyond AGENTS.md

These require reading `docs/ARCHITECTURE.md` end-to-end to discover:

- **Userid length limit** (`docs/ARCHITECTURE.md`, Roles section — userid format) — the assembled
  `{user_prefix}-{role}-{random}@{realm}` must be ≤ 64 chars *including* the realm.
  PVE returns HTTP 400 `user name '<name>@<realm>' is too long (N > 64)`.
  Budget: `len(prefix)+1+len(role)+1+8+1+len(realm) ≤ 64`. Random suffix is 8-char
  base32 (~40 bits). Validate `user_prefix` and role name at **write time**, not issue time.

- **WAL issuance ordering** (`docs/ARCHITECTURE.md`, WAL-Based Orphan Recovery section) —
  generate `nonce = "vault-wal:" + <8-char-random>` → `PutWAL(kind="user", {user_id, nonce})`
  (capture returned WAL id) → `POST /access/users` with `comment=nonce` → **`GET /access/users/{userid}` read-back assert
  group membership** (PVE silently drops unresolvable group ids with HTTP 200; MUST verify
  before minting token) and warn if `comment != nonce` → `POST .../token/lease` → `DeleteWAL` → *then* return the
  Secret. Every step precedes returning the `*logical.Response`; Vault core registers the
  lease after the backend returns and there is no post-lease hook. If `DeleteWAL` fails,
  do **not** return the Secret — best-effort `DELETE` the user and error out. Implement
  `WALRollback` to sweep only nonce-owned orphans: `GetUser`, require live `comment == nonce`,
  then delete. A body `"no such user"` on HTTP 500 is idempotent success for already-gone users
  (PVE never returns 404 for a missing user, Probe 3), but rollback ownership is nonce-gated,
  not body-string-gated. Note also: `PutWAL` returns a WAL id and `DeleteWAL` takes that id,
  not the userid. Do not add compatibility aliases for old WAL payload keys.

- **Lease internalData fields** (`docs/ARCHITECTURE.md`, Storage Schema section) — `pve_userid` (fixed),
  `group` (fixed at issue; the target PVE group, re-sent on every full-replace renewal PUT so
  renewal does not depend on the role still existing), `expire` (rewritten on each renew),
  `role_name` (fixed; read on renew only to load the role's ttl, with fallback to the lease
  TTL if the role is gone), `effective_max_ttl` (fixed at issue, governs renewals). Note:
  these round-trip through JSON as `float64`/`string` — convert, don't assert to `int64`.

- **Single pooled HTTP client** (`docs/ARCHITECTURE.md`, HTTP Client and Connection Pooling section) — one shared client
  built from the stored TLS settings at config-write time, rebuilt on config update.
  Not one client per request.

- **Cluster writes are quorum-gated** (`docs/ARCHITECTURE.md` Proxmox Cluster Considerations) —
  `POST`/`DELETE` on `/access/users` take a cluster-wide lock. Just RETURN the error to Vault
  core on renew/revoke — core's built-in retry/backoff handles quorum loss and lock
  contention. There is NO custom `RetryableError` type (nothing branches on it); do not add
  one unless a call site actually needs it (IMPLEMENTATION_PLAN.md errors.go note).

- **`<mount>/config` DELETE guard** (`README.md`, Vault API Paths table) — ALWAYS requires
  explicit `force=true`. The engine cannot reliably track outstanding leases (no SDK
  lease-count API; a counter drifts on crash/failover), so a conditional "refuse while
  leases exist" check is not feasible. `force=true` is the explicit operator acknowledgement
  that outstanding leases will become non-revocable and non-renewable once the admin credential is removed (renewal also loads config to reach PVE, so it fails immediately too).

`docs/ARCHITECTURE.md` is authoritative for the storage schema, error/compensation
tables, and threat model. Read it before implementing.
