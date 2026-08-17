# AGENTS.md

Instructions for AI coding agents working on this Vault secrets engine plugin.

## Project State

- **Greenfield / design phase.** `docs/ARCHITECTURE.md` is the source of truth — READ IT before implementing anything.
- No Go code, no `go.mod`, no build/test/lint/CI config, and no `.gitignore` exist yet. Bootstrap these before generating artifacts. Add a Go `.gitignore` before creating build artifacts.
- Target: Proxmox VE 9.2.10. This is a Vault secrets engine plugin using `hashicorp/vault/sdk`.

## Critical Gotchas (Agents Get These Wrong)

- **Proxmox enforces anti-privilege-escalation: a non-root@pam token CANNOT grant (via `PUT /access/acl`) a role it doesn't itself hold — returns 403.** Therefore the engine does NOT use per-lease ACL grants. Instead it adds the synthetic user to an operator-PRE-CREATED PVE group that a cluster admin has bound to the desired role. However, the required `User.Modify` at `/access/groups` is **cluster-wide user administration** — a compromised engine token can escalate via two routes: (1) modify its own admin user (`PUT /access/users/<admin user>` with `groups=<privileged group>`), or (2) QUIETER: create a brand-new user directly in a privileged group using the engine's normal workflow — looks like routine activity, harder to spot. Both reach the same privilege ceiling (any role bound to any group). The "never holds the roles it confers" claim is accurate only in the non-compromise case. See `docs/ARCHITECTURE.md` Security Considerations for the full threat model. Confirmed on PVE 9.2.10.

- **`privsep=0` on token creation is MANDATORY.** Proxmox defaults to `privsep=1`, which gives the token its own empty ACL = zero effective permissions (credential silently does nothing). With `privsep=0` the token inherits the synthetic user's ACL. Always send `privsep=0` explicitly on `POST /access/users/{userid}/token/{tokenid}`.

- **Config validation must call `GET /access/permissions`, not just `GET /version`.** `/version` only proves reachability/TLS; it does NOT prove the admin token has the required privileges. Parse the permissions tree at config-time to confirm `User.Modify` at `/access/groups` (parent path) and `Sys.Audit` on `/access/groups`, walking ancestor paths (a grant at `/access` with propagate=1 satisfies requirements for `/access/groups`). The realm-specific `Realm.AllocateUser` at `/access/realm/<realm>` is validated per-role at role-write time (since realm is a per-role field). Surface a 403 clearly.

- **`creds/:role` is a Vault ReadOperation that MUTATES state** (provisions a new PVE user+token per call). Standard dynamic-secrets convention; don't "fix" it to a write.

- **Revocation is idempotent, but keyed on the BODY STRING, not status.** PVE returns HTTP 500 + body `"no such user"` for a DELETE of a nonexistent user (NOT 404 — confirmed PVE 9.2.10, PVE_PROBES.md Probe 3). Treat body `"no such user"` as success.

- **PVE's error contract is body-string, not status-code.** Duplicate user → HTTP **500** body `"already exists"` (in `message`); missing user/group (GET/DELETE) → HTTP **500** body `"no such user"`/`"does not exist"` (in `message`); duplicate tokenid → HTTP **400** with the string `"Token already exists"` in **`errors.tokenid`, NOT `message`** (`message` is just `"Parameter verification failed."` — PVE_PROBES.md Probe 6b). Map errors on the **RAW FULL decoded body** (the `message` string AND all values under the `errors` object), NOT on the `message` field alone, and NOT on 404/409. Only 403 (permission denied) is a genuine status to branch on.

- **`groups` is a `pve-groupid-list`: ONE comma-separated field, never array-repeated.** Single-call create (`POST /access/users` with `groups=<group>`) lands membership and the privsep=0 token inherits the group-derived role (confirmed PVE 9.2.10, PVE_PROBES.md GROUPADD). **PVE silently drops unresolvable group ids and still returns HTTP 200** (observed on modify/append; on create, PVE instead REJECTS with HTTP 500 `"no such group"` — the read-back assertion covers both paths) — every group write MUST be followed by a read-back assertion (`GET /access/users/{id}.groups` or `GET /access/groups/{id}.members`).

- **Renewal must re-`PUT /access/users/{userid}` re-sending `expire`+`groups`+`enable`+`append=1` together.** `PUT /access/users` is **FULL-REPLACE** (confirmed PVE 9.2.10, PVE_PROBES.md Probe 7): an expire-only PUT WIPES the `groups` array and strips the credential's privileges. Read the target group from lease InternalData (not the role), and read the user back to assert membership survived. Both directions are now confirmed on PVE 9.2.10: the full-replace wipe by Probe 7; the preserve path (re-sending `expire`+`groups`+`enable`+`append=1` retains membership, with `groups` and `expire` read back correctly) by Probe RENEWAL-PRESERVE (17 Aug 2026 — groups `["vault-test-grp"]` read back, expire advanced 1786986804→1786990429). The runtime read-back assertion remains as defense-in-depth. Proxmox tokens have no native TTL; the user-level `expire` backstop cuts off the credential when past — confirmed on PVE 9.2.10: a token whose owning USER has an `expire` in the past is rejected at authentication (401).

- **`token_secret` is one-time and non-reproducible.** Never read it back from config or log it. Config GET returns `address`, `tls_skip_verify`, `ca_cert`, `default_ttl`, `default_max_ttl`, and `token_id` — only `token_secret` is withheld.

## API / Path Surface

- `<mount>/config` (POST, GET, DELETE — DELETE requires `force=true`)
- `<mount>/roles/:name` (POST, GET, LIST, DELETE)
- `<mount>/creds/:role` (GET, mutating)
- `<mount>/rotate-root` is OUT OF SCOPE for v1 (manual only)

Engine→Proxmox auth header: `Authorization: PVEAPIToken=<user>@<realm>!<tokenid>=<secret>`

See `docs/ARCHITECTURE.md` for full detail.

## Credential Lifecycle (Order Matters)

**Create:**
1. `POST /access/users` (userid `{user_prefix}-{role}-{random}@{realm}`, no password, `groups=<role.group>` to add the synthetic user to the operator-pre-created PVE group at creation time, `expire=<lease_expiry_unix>`)
2. `GET /access/users/{userid}` — READ-BACK assert `groups` contains `<role.group>` (PVE silently drops unresolvable groups with HTTP 200 on modify/append; on create, PVE instead REJECTS with HTTP 500 `"no such group"` — the read-back assertion covers both paths) before minting token.
3. `POST .../token/{tokenid}` with `privsep=0`

**Revoke:**
Single `DELETE /access/users/{userid}` — cascades to token(s) + group memberships + ACL. Idempotency keys on body `"no such user"` (HTTP 500), not 404. Store `pve_userid` AND `group` in lease internalData (group needed for full-replace renewal).

**No update operation.**

**Mid-create failure:** Best-effort delete the orphaned user (only one post-user step now: token creation). Userid collision (HTTP 500 body "already exists", not 409) → For each suffix attempt: `walID, _ := framework.PutWAL(ctx, storage, kind, walUser{UserID: userid})` (PutWAL RETURNS an id) → attempt `POST /access/users` → on ErrConflict (body "already exists"), call `framework.DeleteWAL(ctx, storage, walID)` with THAT id (the SDK keys WALs by the returned id, NOT by userid), generate a new random suffix (8-character base32, ~40 bits entropy), and loop (bounded retry). On success, proceed to token creation, then DeleteWAL(walID), then return Secret. ALL work (including WAL delete) happens BEFORE returning the Secret. **WAL cleanup discipline**: after a mid-create failure, only DeleteWAL if the compensating DeleteUser returned nil or ErrNotFound; if DeleteUser fails transiently, LEAVE the WAL entry and return the error so walRollback retries (never orphan a user with no WAL entry). Token conflict (HTTP 400 with "Token already exists" in `errors.tokenid`, not 409) → not expected (each lease has a unique fresh userid, and token ids are scoped per-user; if it occurs, treat it exactly like any other CreateToken error — best-effort DeleteUser, then DeleteWAL ONLY if DeleteUser returned nil or ErrNotFound; if DeleteUser fails transiently, leave the WAL entry for walRollback to retry). Surface as internal error.

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

## Testing Convention

- **Acceptance tests:** Prefix `TestAcc*`, gated by `VAULT_ACC=1` (HashiCorp convention), run against a containerized/dev Proxmox — gated CI job, not every PR.
- **Unit tests** use a mocked Proxmox API client.
- Once code exists: `go build ./...`, `go test ./...`, `VAULT_ACC=1 go test ./... -run TestAcc`, `golangci-lint run` (none defined yet — establish them).

## Docs

- `docs/ARCHITECTURE.md` — full design (paths, storage schema, lifecycle, error/compensation, TTLs). Authoritative.
- `README.md` — project overview and usage examples.
