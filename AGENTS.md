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

- **Revocation is idempotent: treat 404 on `DELETE /access/users/{userid}` as success.**

- **Renewal must re-`PUT /access/users/{userid}` with the new `expire` timestamp.** Proxmox tokens have no native TTL; the user-level `expire` is a defense-in-depth backstop that will cut off the credential early if not updated on renew. Confirmed on PVE 9.2.10: a token whose owning USER has an `expire` in the past is rejected at authentication (401).

- **`token_secret` is one-time and non-reproducible.** Never read it back from config or log it. Config GET returns `address`, `tls_skip_verify`, `ca_cert`, `default_ttl`, `default_max_ttl`, and `token_id` — only `token_secret` is withheld.

## API / Path Surface

- `<mount>/config` (POST, GET)
- `<mount>/roles/:name` (POST, GET, LIST, DELETE)
- `<mount>/creds/:role` (GET, mutating)
- `<mount>/rotate-root` is OUT OF SCOPE for v1 (manual only)

Engine→Proxmox auth header: `Authorization: PVEAPIToken=<user>@<realm>!<tokenid>=<secret>`

See `docs/ARCHITECTURE.md` for full detail.

## Credential Lifecycle (Order Matters)

**Create:**
1. `POST /access/users` (userid `{user_prefix}-{role}-{random}@{realm}`, no password, `groups=<role.group>` to add the synthetic user to the operator-pre-created PVE group at creation time, `expire=<lease_expiry_unix>`)
2. `POST .../token/{tokenid}` with `privsep=0`

**Revoke:**
Single `DELETE /access/users/{userid}` — cascades to token(s) + group memberships + ACL. Store `pve_userid` in lease internalData.

**No update operation.**

**Mid-create failure:** Best-effort delete the orphaned user (only one post-user step now: token creation). Userid 409 → For each suffix attempt: `framework.PutWAL(userid)` → attempt `POST /access/users` → on 409, call `framework.DeleteWAL` for that userid, generate a new random suffix (8-character base32, ~40 bits entropy), and loop (bounded retry). On success, proceed to token creation, then DeleteWAL, then return Secret. ALL work (including WAL delete) happens BEFORE returning the Secret. Token 409 → never expected (each lease has unique fresh userid; if it occurs, surface as internal error, do NOT auto-delete as colliding userid would belong to a different active lease).

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

The admin token never needs to hold the delegated roles — those are bound to operator-pre-created PVE groups by a cluster admin out-of-band. Group existence is validated via `GET /access/groups/{group}` at role-write time; the engine does NOT create PVE groups (they must already exist). Role-write also validates `Realm.AllocateUser` at `/access/realm/<role.realm>` via parsing `GET /access/permissions` (with ancestor-path walk).

## TTL Rules

- Effective TTL = min(requested, role.ttl, config.default_ttl, Vault mount/system max)
- Effective max_ttl = min(role.max_ttl, config.default_max_ttl, mount/system max)
- Mount/system max is the hard ceiling
- `effective_max_ttl` is captured in lease internalData at issue time and governs renewals

## Testing Convention

- **Acceptance tests:** Prefix `TestAcc*`, gated by `VAULT_ACC=1` (HashiCorp convention), run against a containerized/dev Proxmox — gated CI job, not every PR.
- **Unit tests** use a mocked Proxmox API client.
- Once code exists: `go build ./...`, `go test ./...`, `VAULT_ACC=1 go test ./... -run TestAcc`, `golangci-lint run` (none defined yet — establish them).

## Docs

- `docs/ARCHITECTURE.md` — full design (paths, storage schema, lifecycle, error/compensation, TTLs). Authoritative.
- `README.md` — project overview and usage examples.
