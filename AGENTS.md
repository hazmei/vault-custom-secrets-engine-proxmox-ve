# AGENTS.md

Instructions for AI coding agents working on this Vault secrets engine plugin.

## Project State

- **Active implementation** through Phase 6 partial validation. Current phase
  validation status, including the recorded PVE build, optional acceptance-test
  skip gates, and production catalog registration status, is tracked in
  `docs/IMPLEMENTATION_PLAN.md`. `docs/ARCHITECTURE.md` and
  `docs/IMPLEMENTATION_PLAN.md` are the authoritative design/status — READ THEM
  before extending.
- Go module (`go.mod`), `.gitignore`, and source exist: `backend.go`, `path_config.go`, `path_roles.go`, `path_creds.go`, `secret_token.go`, `wal.go`, `internal/pveapi/*`, with unit tests throughout.
- Target: Proxmox VE 9.2.10, using `hashicorp/vault/sdk`.

## Critical Gotchas (Agents Get These Wrong)

- **Proxmox enforces anti-privilege-escalation: a non-root@pam token CANNOT grant (via `PUT /access/acl`) a role it doesn't itself hold — returns 403.** Therefore the engine does NOT use per-lease ACL grants. Instead it adds the synthetic user to an operator-PRE-CREATED PVE group that a cluster admin has bound to the desired role. However, the required `User.Modify` at `/access/groups` is **cluster-wide user administration** — a compromised engine token can escalate via two routes: (1) modify its own admin user (`PUT /access/users/<admin user>` with `groups=<privileged group>`), or (2) QUIETER: create a brand-new user directly in a privileged group using the engine's normal workflow — looks like routine activity, harder to spot. Both reach the same privilege ceiling (any role bound to any group). The "never holds the roles it confers" claim is accurate only in the non-compromise case. See `docs/ARCHITECTURE.md` Security Considerations for the full threat model. Confirmed on PVE 9.2.10.

- **`privsep=0` on token creation is MANDATORY.** Proxmox defaults to `privsep=1`, which gives the token its own empty ACL = zero effective permissions (credential silently does nothing). With `privsep=0` the token inherits the synthetic user's ACL. Always send `privsep=0` explicitly on `POST /access/users/{userid}/token/{tokenid}`.

- **Config validation must call `GET /access/permissions`, not just `GET /version`.** `/version` only proves reachability/TLS; it does NOT prove the admin token has the required privileges. Parse the permissions tree at config-time to confirm `User.Modify` at `/access/groups` (parent path) and `Sys.Audit` on `/access/groups`, walking ancestor paths (a grant at `/access` with propagate=1 satisfies requirements for `/access/groups`). The realm-specific `Realm.AllocateUser` at `/access/realm/<realm>` is validated per-role at role-write time (since realm is a per-role field). Surface a 403 clearly.

- **`creds/:role` is a Vault ReadOperation that MUTATES state** (provisions a new PVE user+token per call). Standard dynamic-secrets convention; don't "fix" it to a write.

- **Revocation is idempotent, but keyed on the BODY STRING, not status.** PVE returns HTTP 500 + body `"no such user"` for a DELETE of a nonexistent user (NOT 404 — confirmed PVE 9.2.10, PVE_PROBES.md Probe 3). Treat body `"no such user"` as success.

- **WAL crash-recovery rollback is NONCE-gated, NOT body-string-gated (distinct from revoke).** Each issuance attempt generates `nonce = walCommentPrefix + random` (`walCommentPrefix = "vault-wal:"`), stored in BOTH the WAL entry (`walUser.Nonce`) AND the PVE user's `comment` field (`CreateUserRequest.Comment`). `walRollbackUser` verifies ownership before deleting: `GetUser` first → `ErrUserNotFound` → nil; `comment == nonce` → our orphan → `DeleteUser`; `info.Comment != entry.Nonce` (mismatch — comment was edited or dropped on create) OR `entry.Nonce == ""` (empty WAL nonce — WAL entry predates the nonce scheme, i.e. written before commit c9338e0; any such in-flight entry across that upgrade will refuse to clean its user) → `Error` log + return nil (DROP the WAL entry WITHOUT deleting the user); transient `GetUser` error → return err (retry). The revoke path (`secretTokenRevoke`) is separate and still keys idempotency purely on body `"no such user"`.

- **PVE `comment` round-trips byte-for-byte (PVE_PROBES.md Probe COMMENT, confirmed 9.2.10)** and survives the engine's renewal PUT (`append=1`, comment omitted — confirmed 19 Aug 2026). The WAL nonce marker relies on this. Operators MUST NOT hand-edit the `comment` field on `vault-*` users — it defeats WAL-based cleanup (`walRollbackUser` will treat the user as foreign and skip deletion). Note: only the `append=1` renewal shape was probed; general full-replace semantics for `comment` (a PUT without `append=1`) were not tested and are not relied upon.

- **PVE's error contract is body-string for business errors, with 401/403 as genuine status codes.** Duplicate user → HTTP **500** body `"already exists"` (in `message`); missing user/group (GET/DELETE) → HTTP **500** body `"no such user"`/`"does not exist"` (in `message`); duplicate tokenid → HTTP **400** with the string `"Token already exists"` in **`errors.tokenid`, NOT `message`** (`message` is just `"Parameter verification failed."` — PVE_PROBES.md Probe 6b). Map business errors on the **RAW FULL decoded body** (the `message` string AND all values under the `errors` object), NOT on the `message` field alone, and NOT on 404/409. HTTP 401 (unauthenticated/dead token) and HTTP 403 (permission denied) are genuine statuses to branch on before body-string classification.

- **PVE response bodies are hard-capped at 1 MiB using N+1 truncation detection.** The real client reads at most `maxResponseBodyBytes+1` bytes and returns `ErrResponseTooLarge` before JSON parsing or body-string business-error classification. Do NOT replace this with a naive `io.LimitReader(resp.Body, maxResponseBodyBytes)` that silently truncates and then classifies a partial body. Oversized responses fail closed: even an HTTP 500 DELETE body containing `"no such user"` must NOT become `ErrUserNotFound`/idempotent success unless the complete response fits under the cap. Do not add config knobs or weaken the cap.

- **`groups` is a `pve-groupid-list`: ONE comma-separated field, never array-repeated.** Single-call create (`POST /access/users` with `groups=<group>`) lands membership and the privsep=0 token inherits the group-derived role (confirmed PVE 9.2.10, PVE_PROBES.md GROUPADD). **PVE silently drops unresolvable group ids and still returns HTTP 200** (observed on modify/append; on create, PVE instead REJECTS with HTTP 500 `"no such group"` — the read-back assertion covers both paths) — every group write MUST be followed by a read-back assertion (`GET /access/users/{id}.groups` or `GET /access/groups/{id}.members`).

- **Renewal must re-`PUT /access/users/{userid}` re-sending `expire`+`groups`+`enable`+`append=1` together.** Historical PVE 9.2.10 Probe 7 showed replacement-style updates can wipe the `groups` array and strip the credential's privileges; a later live acceptance run on PVE manager 9.2.10 build `43df2e01f27a1a19` preserved groups when `append` was omitted, so omitted-`append` semantics are unresolved and must not be relied upon. Read the target group from lease InternalData (not the role), send explicit `append=1`, and read the user back to assert membership survived. The preserve path (re-sending `expire`+`groups`+`enable`+`append=1` retains membership, with `groups` and `expire` read back correctly) is confirmed by Probe RENEWAL-PRESERVE (17 Aug 2026 — groups `["vault-test-grp"]` read back, expire advanced 1786986804→1786990429). The runtime read-back assertion remains as defense-in-depth. Proxmox tokens have no native TTL; the user-level `expire` backstop cuts off the credential when past — confirmed on PVE 9.2.10: a token whose owning USER has an `expire` in the past is rejected at authentication (401).

- **Password mode (`mode=password` on a role) mints NO API token.** The password is supplied on the SAME `POST /access/users` call that creates the user (confirmed PVE 9.2.10, PVE_PROBES.md Probe P0), so the credential is LIVE the instant that call returns 200 — before the group read-back and before `DeleteWAL`. Consequences that differ from token mode: (1) every post-create failure must DELETE the user, not just log; (2) a `comment != nonce` read-back mismatch is **FATAL** in password mode (delete the user, fail issuance) whereas token mode only warns — a live credential whose WAL ownership marker is already broken must never be handed out; (3) `CreateToken` must never be called. The engine NEVER rotates a password: `PUT /access/password` requires a password-authenticated ticket that API-token auth cannot obtain (Probe P0). Password roles are restricted to the `pve` realm — PAM password creation FAILED in the automated probe run and its reported auth/rotation behavior is unreproduced. Renewal is the same `expire`+`groups`+`enable`+`append=1` PUT as token mode and preserves the ORIGINAL password (Probe P0).

- **`token_secret` is one-time and non-reproducible.** Never read it back from config or log it. Config GET returns `address`, `tls_skip_verify`, `ca_cert`, `default_ttl`, `default_max_ttl`, and `token_id` — only `token_secret` is withheld.

## API / Path Surface

- `<mount>/config` (POST, GET, DELETE — DELETE requires `force=true`)
- `<mount>/roles/:name` (POST, GET, LIST, DELETE) — `mode` selects the credential type: `token` (default; absent/empty on legacy roles normalizes to `token` in `getRole`) or `password`
- `<mount>/creds/:role` (GET, mutating) — sets `ForwardPerformanceStandby: true` and `ForwardPerformanceSecondary: true` on the `PathOperation`. **This is mandatory, not optional.** Issuance makes external mutating PVE calls (CreateUser, CreateToken) BEFORE writing any Vault storage. If a standby node executed this path locally it would call PVE and then forward the storage write to the active — producing a duplicate PVE user with no WAL entry and no lease. Forwarding the entire request to the active node before any PVE call is the only correct fix; Vault's implicit write-forwarding does not help here.
- `<mount>/rotate-root` is OUT OF SCOPE for v1 (manual only)

Engine→Proxmox auth header: `Authorization: PVEAPIToken=<user>@<realm>!<tokenid>=<secret>`

See `docs/ARCHITECTURE.md` for full detail.

## Credential Lifecycle (Order Matters)

**Create:**
1. `POST /access/users` (userid `{user_prefix}-{role}-{random}@{realm}`, no password, `groups=<role.group>` to add the synthetic user to the operator-pre-created PVE group at creation time, `expire=<lease_end_unix + 60>` (60s grace, const `expireGraceSecs`, absorbs Vault↔PVE clock drift), `comment=<nonce>` where `nonce = walCommentPrefix + random` — ownership marker for WAL rollback). Per-lease tokenid is the fixed const `leaseTokenID="lease"` (scoped per unique userid; no cross-lease collision).
2. `GET /access/users/{userid}` — READ-BACK assert `groups` contains `<role.group>` (PVE silently drops unresolvable groups with HTTP 200 on modify/append; on create, PVE instead REJECTS with HTTP 500 `"no such group"` — the read-back assertion covers both paths) before minting token; also soft-`Warn` (non-fatal) if the read-back `comment != nonce`, since a lost marker only disables WAL-based crash-recovery cleanup for that user (the direct revocation path is unaffected).
3. `POST .../token/{tokenid}` with `privsep=0`

**Renew:**
1. Extract `pve_userid`+`group`+`effective_max_ttl`+`role_name`+`expire` from InternalData.
2. Compute new TTL via `framework.CalculateTTL` (role.ttl via `role_name` if the role exists, else the lease's current TTL; positive requested increment wins; capped at `effective_max_ttl`).
3. Pre-update `GetUser`: REFUSE renewal if the user is disabled (`Enable == false`) — do NOT silently re-enable (an operator may have disabled it for incident response). TOCTOU window noted; no conditional-update PVE API exists.
4. `PUT /access/users/{userid}` full-replace: `expire`+`groups`+`enable`+`append=1`.
5. Read-back `GetUser`: HARD-fail if the group is missing; soft `Warn` if `len(groups) != 1`.
6. Rewrite `expire` in InternalData; return the updated Secret.

(There is no standalone PVE user-update path; renewal reuses the full-replace PUT.)

**Lease InternalData schema** (stored at issuance, read by Renew and Revoke):
`pve_userid`, `group` (for full-replace renewal), `effective_max_ttl` (int64 ns; renewal ceiling), `role_name` (optional; renewal TTL fallback — absent on leases issued before c9338e0 → renewal falls back to the lease's current TTL), and `expire` (Unix epoch; rewritten on each renewal).

**Revoke:**
Single `DELETE /access/users/{userid}` — cascades to token(s) + group memberships + ACL. Only `pve_userid` is consumed (the cascade removes everything). Idempotency keys on body `"no such user"` (HTTP 500), not 404.

**Mid-create failure:** Best-effort delete the orphaned user (only one post-user step now: token creation). Userid collision (HTTP 500 body "already exists", not 409) → For each suffix attempt: `walID, _ := framework.PutWAL(ctx, storage, kind, walUser{UserID: userid, Nonce: nonce})` (PutWAL RETURNS an id) → attempt `POST /access/users` → on ErrConflict (body "already exists"), call `framework.DeleteWAL(ctx, storage, walID)` with THAT id (the SDK keys WALs by the returned id, NOT by userid); if `DeleteWAL` itself FAILS, HARD-RETURN (abort issuance, surface the error) — safe because the nonce/comment ownership check prevents `walRollback` from deleting the foreign colliding user. On `DeleteWAL` success, generate a new random suffix (8-character base32, ~40 bits entropy), and loop (bounded, `maxCollisionRetries = 5`). On success, proceed to token creation, then DeleteWAL(walID), then return Secret. ALL work (including WAL delete) happens BEFORE returning the Secret. **WAL cleanup discipline**: after a mid-create failure, only DeleteWAL if the compensating DeleteUser returned nil or ErrUserNotFound; if DeleteUser fails transiently, LEAVE the WAL entry and return the error so walRollback retries (never orphan a user with no WAL entry). Token conflict (HTTP 400 with "Token already exists" in `errors.tokenid`, not 409) → not expected (each lease has a unique fresh userid, and token ids are scoped per-user; if it occurs, treat it exactly like any other CreateToken error — best-effort DeleteUser, then DeleteWAL ONLY if DeleteUser returned nil or ErrUserNotFound; if DeleteUser fails transiently, leave the WAL entry for walRollback to retry). Surface as internal error.

## Admin (Root) Token Privileges

Recommended least-privilege PVE role: `User.Modify`, `Realm.AllocateUser`, `Sys.Audit`, plus token management.

**Required privilege scoping** (confirmed on PVE 9.2.10):
- `User.Modify` on `/access/groups` (PARENT PATH) — required for user creation, renewal (PUT expire), and revocation
- `Realm.AllocateUser` on `/access/realm/<realm>` (per realm)
- `Sys.Audit` on `/access/groups` — for group-existence validation. **Trade-off**: Required ONLY for early failure (validating group existence at role-write time). An alternative is to drop the precheck and let credential issuance fail if the group is missing, which removes `Sys.Audit` from the required set. The precheck approach is recommended for better operator ergonomics.

**Literal ACL grant commands**:
```bash
# Create a custom VaultProvisioner role with User.Modify, Realm.AllocateUser, Sys.Audit
pveum acl modify /access/groups --user vault-admin@pve --role VaultProvisioner --propagate 1
pveum acl modify /access/realm/pve --user vault-admin@pve --role VaultProvisioner
```

**IMPORTANT**: The `/access/groups` grant MUST be propagating (`--propagate 1`, PVE default). The parent-path grant satisfies renewal/revocation (parent check) AND creation's per-group check at `/access/groups/<group>` ONLY via propagation. An operator who sets `--propagate 0` gets a broken partial config: creation 403s (per-group check unsatisfied) while renew/revoke still work. Always use propagating grants.

**Per-operation privilege-path asymmetry** (discovered in live testing):
- User creation (`POST /access/users` with `groups=<group>`) checks `User.Modify` at the PER-GROUP path `/access/groups/<group>` AND `Realm.AllocateUser` at `/access/realm/<realm>`.
- User renewal (`PUT /access/users/{userid}` with `expire` only) and revocation (`DELETE /access/users/{userid}`) check `User.Modify` at the PARENT `/access/groups` (NOT per-group).
- Because PVE's user-update and user-delete endpoints check the PARENT path, per-group scoping is NOT achievable for renewal and revocation.

**Blast radius and threat model**: See `docs/ARCHITECTURE.md` Security Considerations for the complete threat model, including cluster-wide user administration, self-escalation primitives (both admin-self-modification and the quieter new-user-in-privileged-group route), honest comparison to full-admin, and containment recommendations.

The admin token never needs to hold the delegated roles — those are bound to operator-pre-created PVE groups by a cluster admin out-of-band. Group existence is validated via `GET /access/groups/{group}` at role-write time; the engine does NOT create PVE groups (they must already exist). Role-write also validates `Realm.AllocateUser` at `/access/realm/<role.realm>` via parsing `GET /access/permissions` (with ancestor-path walk). Role-write also verifies `User.Modify` is effective at the **per-group path** `/access/groups/<role.group>` (the propagate flag is visible as `:0`/`:1`, PVE_PROBES.md Probe 9) to catch a `--propagate 0` grant at `/access/groups` that would pass the parent check but fail user creation.

## TTL Rules

- **Effective TTL**: `role.ttl` if set, else `config.default_ttl` if set, else Vault system default; capped at the effective max_ttl. (`config.default_ttl` is a **FALLBACK**, not a cap — treating it as a min() cap collapses TTL to 0 when role values are unset.)
- **Effective max_ttl**: `role.max_ttl` if set, else `config.default_max_ttl` if set; capped at Vault mount/system max (the hard ceiling).
- Computed via `framework.CalculateTTL` (Locked Decision #8) — **NOT** a hand-rolled `min()`, which mishandles unset-vs-zero (an unset value of 0 would collapse the effective TTL to 0 rather than falling back).
- There is no issuance-time requested TTL (`creds/:role` declares no `ttl` field); the requested `increment` applies only on lease renewal.
- `effective_max_ttl` is captured in lease internalData at issue time and governs renewals.
- **Renewal-time `backendTTL` (no explicit increment):** `role.ttl` (loaded via `role_name`) if the role still exists; else `req.Secret.TTL` (the lease's CURRENT TTL) — NOT the mount default — so deleted-role or pre-`role_name` leases renew coherently. A positive requested increment overrides via `CalculateTTL`.

## Testing Convention

- **Acceptance tests:** Prefix `TestAcc*`, gated by `VAULT_ACC=1` (HashiCorp convention), run only by an operator against a disposable/dev Proxmox cluster. They are never run by CI.
- **Unit tests** use a mocked PVE client (`internal/pveapi/mock.go`).
- Run: `go build ./...`, `make test`, `make testacc` (operator-run live
  acceptance with required env preflight), `make lint`, `make verify-artifact`
  (operator-run artifact and permission verification with the required
  `EXPECTED_SHA`, `EXPECTED_OWNER`, and `PLUGIN_DIR` environment variables),
  `make smoke` (the `verify-plugin-artifact` smoke checks — the same script CI
  runs, so it is runnable locally before pushing).
- **`make smoke` fixture location:** the smoke script builds its fixture under
  `$RUNNER_TEMP`, falling back to `.smoke-tmp/` in the repo root (gitignored).
  It aborts with an explicit message if any ancestor of that directory is
  group/other writable, because `verify-plugin-artifact.sh` walks every ancestor
  to `/` and fails on writable ones — without the precheck a checkout under a
  shared path fails as `direct positive: rc=1 want=0` with no hint that the
  fixture's own location is at fault. Set `RUNNER_TEMP` to a private directory
  in that case. On a host without GNU coreutils/findutils (macOS/BSD, where the
  verifier's `sha256sum`/`stat -c`/`find -perm /022` probes fail), the smoke
  script probes the same three tools up front and **skips cleanly** (`exit 0`
  with a `brew install coreutils findutils` hint) instead of asserting the
  verifier exits 0 and surfacing that same opaque `direct positive` line —
  **unless `CI` is set** (to anything other than the `false`/`0` opt-out), where
  it instead refuses to skip and exits 1 so the CI gate cannot silently
  self-disable. Full execution therefore runs on Linux/CI.
- **CI** (`.github/workflows/ci.yml`) runs build + unit tests + golangci-lint (pinned v2.12.2), ShellCheck, and the `verify-plugin-artifact` smoke test on every push/PR. The smoke step invokes the same `scripts/verify-plugin-artifact-smoke.sh` as `make smoke`. The lint version is pinned in the Makefile (`GOLANGCI_LINT_VERSION`) so local and CI agree.

## Docs

- `docs/ARCHITECTURE.md` — full design (paths, storage schema, lifecycle, error/compensation, TTLs). Authoritative.
- `docs/IMPLEMENTATION_PLAN.md` — phased implementation tasks and locked decisions.
- `docs/PRODUCTION_VERIFICATION.md` — operator-run production verification procedure (artifact integrity, catalog registration, lifecycle, HA/failover).
- `docs/PVE_PROBES.md` — PVE behavior probe evidence (confirmed on PVE 9.2.10).
- `README.md` — project overview and usage examples.
