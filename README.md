# Proxmox VE Secrets Engine for HashiCorp Vault

A HashiCorp Vault custom secrets engine plugin that issues **dynamic, per-lease Proxmox VE API tokens** with scoped access control and automatic cleanup on revocation.

## Overview

This secrets engine implements Vault's dynamic secrets pattern for Proxmox VE. Each credential lease creates a dedicated, throwaway Proxmox user, adds it to an operator-pre-created PVE group (which the operator has already bound to the desired ACL role(s)), and mints an API token bound to that user. On revocation, a single delete operation removes the user, which cascades to clean up the token, group memberships, and all ACL entries. Orphaned credentials created mid-provision (e.g., from Vault process death or failover) are eventually swept via Vault's Write-Ahead Log (WAL) rollback mechanism.

**Target Platform**: Proxmox VE 9.2.10

## Project Status

🚧 **Active implementation** — Core plugin code, unit tests, and operator-run
live acceptance tests are present. Phase 5 operator-run live acceptance passed
on the operator's Proxmox VE 9.2.10 build on 2026-08-20 with the required tests
green; optional canaries that lacked environment variables remained skipped.
Phase 6 `make build` and local Vault plugin registration/enable/`force=true`
config-delete checks passed. A full Vault-server lifecycle smoke test that
issues, uses, renews, and revokes a live credential remains pending because the
execution environment did not provide the required `PVE_*` variables.

## How It Works

### Credential Lifecycle

1. **Create** (on `GET <mount>/creds/:role`):
   - Creates a synthetic Proxmox user: `{prefix}-{role}-{random}@{realm}` with `groups=<role.group>` at creation time
   - Mints an API token on the user with `privsep=0` (inherits user ACL)
   - Returns `token_id` and `token_secret` (shown only once, non-reproducible)

2. **Renew**:
   - Extends Vault lease TTL up to the effective `max_ttl` (measured from the original issue time)
   - Refuses renewal if the PVE user was disabled out-of-band, preserving that operator kill switch
   - Issues `PUT /access/users/{userid}` re-sending `expire`+`groups`+`enable`+`append=1` **together**. Historical PVE 9.2.10 Probe 7 showed replacement-style updates can wipe group membership and strip privileges; a later live acceptance run preserved groups when `append` was omitted, so omitted-`append` semantics are unresolved and not relied upon. The target group is read from the lease's internal data, and a read-back confirms membership survived. The preserve path (re-sending groups with explicit `append=1`) is confirmed by Probe RENEWAL-PRESERVE (17 Aug 2026 — groups `["vault-test-grp"]` read back, expire advanced 1786986804→1786990429). The runtime read-back remains as defense-in-depth.

3. **Revoke**:
   - Single `DELETE /access/users/{userid}` call
   - Cascades to automatically remove the user's token(s), group memberships, and ACL entries
   - Idempotent (PVE returns HTTP 500 + body `"no such user"` for a missing user, NOT 404; the engine keys idempotency on that body string — confirmed PVE 9.2.10)

### Security Design

- **Per-lease isolation**: Each credential gets a unique throwaway user identity
- **Cascade deletion**: Single API call cleans up user, tokens, group memberships, and ACL entries atomically
- **Scoped permissions**: Tokens inherit scoped ACL from the synthetic user (via the user's group membership; the group's ACL path, roles, and propagate flag are operator-controlled)
- **Backstop expiry**: Proxmox-side `expire` timestamp on the synthetic user provides defense-in-depth if Vault revocation is delayed (confirmed on PVE 9.2.10: token auth rejected when owning user's `expire` is past)
- **Least-privilege admin token**: Root configuration token uses a custom role with only `User.Modify` + `Realm.AllocateUser` + `Sys.Audit`, scoped to `/access/groups` (parent path, propagating), `/access/realm/<realm>`, and `/access/groups` respectively (see Prerequisites for full privilege requirements and the Security Considerations section in docs/ARCHITECTURE.md for the complete threat model and blast-radius analysis)

## Vault API Paths

| Path | Operations | Description |
|------|-----------|-------------|
| `<mount>/config` | POST, GET, DELETE | Configure Proxmox connection (address, admin token, TLS, default TTLs); GET returns `address`, `tls_skip_verify`, `ca_cert`, `default_ttl`, `default_max_ttl`, `token_id`; `token_secret` never returned; DELETE requires `force=true` — outstanding leases become non-revocable and non-renewable (renewal also loads config to reach PVE, so it fails immediately too; revoke them first) |
| `<mount>/roles/:name` | POST, GET, LIST, DELETE | Define credential roles with group name, TTLs, and user prefix; DELETE does not revoke outstanding leases |
| `<mount>/creds/:role` | GET | Issue a new dynamic credential (returns `user_id`, `token_id`, `token_secret`) |
| `<mount>/rotate-root` | — | **Out of scope for v1** — root token rotation is manual (documented as create new token → update config → delete old token) |

## Requirements / Prerequisites

### Vault
- HashiCorp Vault (compatible with secrets engine plugin SDK)

### Proxmox VE
- Proxmox VE 9.2.10 or compatible
- Network access to Proxmox API: `https://<host>:8006/api2/json`

### Admin Token Configuration
The engine requires a Proxmox API token with privileges to manage users, tokens, and group membership. Two approaches:

**Recommended (Least-Privilege)**:
- Create a **custom Proxmox role** with only the required permissions:
  - `User.Modify` — create and delete users, manage group membership
  - `Realm.AllocateUser` — allocate users in the target realm
  - `Sys.Audit` — read group metadata for validation
  - Token management capabilities
- **Required privilege scoping** (confirmed on PVE 9.2.10):
  - `User.Modify` on `/access/groups` (PARENT PATH) — required for user creation, renewal, and revocation
  - `Realm.AllocateUser` on `/access/realm/<realm>` (e.g., `/access/realm/pve`)
  - `Sys.Audit` on `/access/groups` — required for group-existence validation at role-write time. **Trade-off**: This privilege is required ONLY to enable early failure (validating group existence at role-write time). An alternative is to drop the precheck and let credential issuance fail if the group is missing, which removes `Sys.Audit` from the required set. The precheck + `Sys.Audit` approach is recommended for better operator ergonomics.
- **Literal ACL grant commands**:
  ```bash
  # Create a custom VaultProvisioner role with User.Modify, Realm.AllocateUser, Sys.Audit
  pveum acl modify /access/groups --user vault-admin@pve --role VaultProvisioner --propagate 1
  pveum acl modify /access/realm/pve --user vault-admin@pve --role VaultProvisioner
  ```
  **IMPORTANT**: The `/access/groups` grant MUST be propagating (`--propagate 1`, which is PVE's default). The parent-path grant at `/access/groups` satisfies the renewal/revocation privilege check (which PVE checks at the parent) AND satisfies the creation per-group check at `/access/groups/<group>` ONLY via propagation. An operator who sets `--propagate 0` gets a broken partial config: user creation will 403 (per-group check unsatisfied) while renew/revoke still work — a confusing partial failure. Always use propagating grants for `/access/groups`.
- **Per-operation privilege-path asymmetry** (discovered in live testing):
  - User creation (`POST /access/users` with `groups=<group>`) checks `User.Modify` at the PER-GROUP path `/access/groups/<group>` AND `Realm.AllocateUser` at `/access/realm/<realm>`.
  - User renewal (`PUT /access/users/{userid}` with `expire` only) and revocation (`DELETE /access/users/{userid}`) check `User.Modify` at the PARENT `/access/groups` (NOT per-group).
  - Because PVE's user-update and user-delete endpoints check the PARENT path, per-group scoping is NOT achievable for renewal and revocation. The admin token must hold `User.Modify` at `/access/groups` (parent), which propagates to all child group paths.

**Blast radius and threat model**: See the Security Considerations section in `docs/ARCHITECTURE.md` for the complete threat model analysis, including the cluster-wide user administration blast radius, self-escalation primitives in the compromise case (both the admin-self-modification route and the quieter new-user-in-privileged-group route), honest comparison to full-admin, and partial containment recommendations.

**Why group membership instead of direct ACL grants?** Proxmox enforces
anti-privilege-escalation on `PUT /access/acl`: a principal cannot grant
roles it does not hold (confirmed on PVE 9.2.10: a token lacking
PVEVMAdmin at `/vms/200` receives `403: Permission check failed
(/vms/200, Permissions.Modify|VM.Allocate)` when attempting to grant that
role). By using **group membership**, the engine's admin token avoids
holding the delegated roles directly in the non-compromise case — those are bound to groups once by
a cluster admin (typically `root@pam`). Group-membership writes are
authorized solely by `User.Modify`. However, the required `User.Modify` at `/access/groups` is cluster-wide user administration; see the Security Considerations section in `docs/ARCHITECTURE.md` for the full threat model.

**Acceptable Fallback**:
- Use a full-admin token (e.g., `root@pam` or `PVEAdmin`-equivalent at `/`)
- Can bypass anti-escalation checks and has broader initial blast radius (direct ACL/resource management permissions in addition to user admin)
- The group model is preferred when operators can pre-create groups and want to avoid granting direct ACL/resource management permissions; it narrows the initial blast radius but does not achieve true least-privilege in the compromise case

The engine validates the admin token's connectivity and privileges at
configuration time via `GET /version` (reachability/TLS) and
`GET /access/permissions` (privilege verification, parsed as a tree for
the specific `User.Modify` and `Sys.Audit` on `/access/groups`; the
realm-specific `Realm.AllocateUser` at `/access/realm/<realm>` is
validated per-role at role-write time). The privilege check walks
ancestor paths (a grant at `/access` with `propagate=1` satisfies
requirements for `/access/groups`).

## Configuration Example

```bash
# Configure the secrets engine
vault write pve/config \
  address="https://pve.example.com:8006" \
  token_id="vault-admin@pve!root-token" \
  token_secret="<uuid-secret>" \
  tls_skip_verify=false \
  ca_cert=@ca-bundle.pem \
  default_ttl=3600 \
  default_max_ttl=86400

# Create a role for VM administrators
# (Assumes a PVE group "vault-vm-admins" already exists and is bound to PVEVMAdmin at /vms/100)
vault write pve/roles/vm-admin \
  group="vault-vm-admins" \
  user_prefix="vault" \
  realm="pve" \
  ttl=3600 \
  max_ttl=86400

# Issue a credential
vault read pve/creds/vm-admin
# Returns: user_id, token_id, token_secret (lease auto-revokes on expiry)
```

## TTL and Renewal Behavior

**At credential issuance**, the effective TTL and max_ttl are computed using
role values with config defaults as fallbacks:

```
role_ttl     = role.ttl     or config.default_ttl
role_max_ttl = role.max_ttl or config.default_max_ttl
eff_max_ttl  = min(role_max_ttl, Vault mount/system max TTL)
eff_ttl      = min(role_ttl, eff_max_ttl)          # no requested TTL at issuance
```

Key points:
- `config.default_ttl` and `config.default_max_ttl` are **fallback values** used only when the role does not define its own `ttl` or `max_ttl`.
- **There is no issuance-time requested TTL**: `<mount>/creds/:role` declares no `ttl` field (matching the database and terraform secrets engines). A requested `increment` only applies on lease RENEWAL (`req.Secret.Increment`), capped at `eff_max_ttl` measured from the original issue time.
- Vault's mount/system maximum TTL remains the absolute hard ceiling.
- **Unlimited (zero) TTL is refused at issuance**: if the role and config resolve to no finite TTL, `vault read <mount>/creds/:role` returns an error. The Proxmox-side `expire` backstop requires a finite lease; a never-expiring user would disable it. Set a non-zero `ttl`/`max_ttl` on the role or a config default.

**On lease renewal**:
- Lease TTL extends up to the effective `max_ttl` captured at issue time
- Proxmox-side user `expire` backstop is updated to match the new expiry

## Documentation

- **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** — Complete architecture and design specification, including:
  - Detailed API call sequences and parameters
  - Error handling and compensation logic (orphaned user cleanup, retry strategies, WAL-based crash recovery)
  - Storage schema (config, roles, lease internal data)
  - TTL precedence rules and renewal behavior
  - Security considerations and threat model
  - Proxmox cluster considerations (quorum, lock contention)

## Testing Strategy

### Unit Tests
- Mocked Proxmox API client for isolated path handler testing
- Input validation, TTL computation, error mapping
- Compensation paths (orphaned user cleanup on mid-provisioning failure)
- Idempotent deletion (body `"no such user"` on HTTP 500 treated as success, not a 404 status)
- Userid sanitization (character set and length limit validation)

### Acceptance Tests
- Environment gating: `VAULT_ACC=1` (HashiCorp convention)
- Full lifecycle: pre-create a safe PVE group bound to a test role → issue credential → run a `/version` authentication smoke check with the issued token → renew lease → revoke and confirm cleanup.
- Authorization contract canary: requires `PVE_BEHAVIORAL_PATH` and `PVE_BEHAVIORAL_MARKER`; the issued token must receive HTTP 200 from that group-role-gated endpoint and the body must contain the marker. Optional subtests cover direct `PUT /access/acl` anti-privilege-escalation (configured unheld role must return 403) and negative authorization with expected 403. Unconfigured optional subtests skip with explicit prerequisites rather than assuming full-admin or cluster-specific endpoints.
- Failure coverage: idempotent revocation after an issued PVE user is deleted out-of-band, WAL rollback, delete-config guard, configurable concurrent issuance, and optional insufficient-privilege config validation in `TestAccInsufficientPrivileges`.
- Unit tests cover deterministic mid-provisioning network/error injection and WAL-delete failure paths. The live acceptance suite does not inject network failures, quorum loss, or ACL lock contention.
- Run against an operator-provided disposable/dev Proxmox VE 9.2.10 cluster with a test admin token. These tests mutate the cluster by creating, renewing, expiring, and deleting temporary `vaultacc-*@pve` users.
- Live acceptance tests are operator-run only and are never run by CI. Normal PR CI runs build, unit tests, and lint only.
- Last recorded operator result: required Phase 5 `make testacc` tests passed
  against the operator's PVE 9.2.10 build on 2026-08-20; optional canaries
  without configured `PVE_*` prerequisites remained skipped.

#### Acceptance Test Prerequisites

The root `acceptance_test.go` suite mutates a live Proxmox VE cluster. Run it
only against a disposable/dev cluster or a production-like cluster where
temporary `vaultacc-*@pve` users can be safely created, expired, renewed, and
deleted. The suite targets the PVE 9.2.10 behavior documented in
`docs/PVE_PROBES.md`.

Create a dedicated acceptance provisioner identity instead of reusing a human or
full-admin token. Run these commands as a Proxmox cluster administrator on an
isolated/disposable test cluster, replacing only the example names if needed:

```bash
# Dedicated API-token owner used only by Vault acceptance tests.
pveum user add vault-acc@pve --comment "Vault acceptance test provisioner"

# Custom role with the privileges the engine validates and uses.
pveum role add VaultAccProvisioner \
  --privs "User.Modify Realm.AllocateUser Sys.Audit"

# The /access/groups grant must propagate to /access/groups/<PVE_TEST_GROUP>.
pveum acl modify /access/groups \
  --user vault-acc@pve \
  --role VaultAccProvisioner \
  --propagate 1

# Realm allocation is validated per role. Keep it scoped to the test realm.
pveum acl modify /access/realm/pve \
  --user vault-acc@pve \
  --role VaultAccProvisioner \
  --propagate 1

# Create the API token with privsep=0 so it inherits vault-acc@pve ACLs.
pveum user token add vault-acc@pve acceptance \
  --privsep 0 \
  --comment "Vault acceptance test token"
```

The final command prints the token secret one time. PVE token IDs use the form
`user@realm!tokenid`; in the example above, the token **ID** is
`vault-acc@pve!acceptance`. The token **secret** is the generated `value` field.
The ID alone is not a usable credential; the secret is the sensitive half of the
`Authorization: PVEAPIToken=<id>=<secret>` pair. Copy the secret directly into
your local shell or secret manager, do not commit it, and do not paste it into
logs, issues, PRs, or documentation.

`PVE_TEST_GROUP` must also be pre-created and bound by a cluster administrator
to the role/path you want issued test credentials to exercise. The engine does
not create PVE groups. The acceptance suite will create temporary users in this
group, then verify that an issued token can access `PVE_BEHAVIORAL_PATH` and
that the response contains `PVE_BEHAVIORAL_MARKER`. For example, on a disposable
cluster only:

```bash
pveum group add vault-test-grp --comment "Vault acceptance test group"

# Example only: choose a role/path appropriate for your disposable test cluster
# and make PVE_BEHAVIORAL_PATH point at an endpoint protected by this binding.
pveum acl modify / \
  --group vault-test-grp \
  --role PVEAuditor \
  --propagate 1
```

With the example `PVE_BEHAVIORAL_PATH` and `PVE_BEHAVIORAL_MARKER` below, the
test cluster must have at least one qemu VM visible through the group-role
binding. A stopped stub VM is sufficient; an empty cluster returns HTTP 200 with
an empty `/cluster/resources?type=vm` list, which does not prove the issued
token has the delegated authorization and will fail the marker canary.

Required environment:

```bash
export VAULT_ACC=1
export PVE_ADDR="https://pve.example.com:8006"
export PVE_TOKEN_ID="vault-acc@pve!acceptance"
export PVE_TOKEN_SECRET="<one-time-secret-from-pveum-user-token-add>"
export PVE_TEST_GROUP="vault-test-grp"
export PVE_BEHAVIORAL_PATH="/cluster/resources?type=vm"
export PVE_BEHAVIORAL_MARKER='"type":"qemu"'
```

`PVE_TEST_GROUP` must already exist. The admin token must pass the engine's
normal config and role validation: `User.Modify` at `/access/groups` with
propagation to `/access/groups/<PVE_TEST_GROUP>`, `Sys.Audit` at
`/access/groups`, and `Realm.AllocateUser` at `/access/realm/pve`.

The lifecycle test always uses `GET /version` as an authentication smoke check
only. The canonical `make testacc` preflight requires an endpoint protected by
the test group's role and a response marker that must appear in the body for the
authoritative authorization canary; bare HTTP 200 is not treated as proof:

```bash
export PVE_BEHAVIORAL_PATH="/cluster/resources?type=vm"
export PVE_BEHAVIORAL_METHOD="GET"
export PVE_BEHAVIORAL_MARKER='"type":"qemu"'
```

Optional negative authorization check:

```bash
export PVE_NEGATIVE_AUTH_PATH="/nodes/pve/qemu/100/config"
export PVE_NEGATIVE_AUTH_METHOD="GET"
```

Optional direct ACL anti-privilege-escalation canary. Use only with a
non-full-admin token and a role the token does not hold at the target path; the
test expects `PUT /access/acl` to return 403:

```bash
export PVE_ACL_CANARY_PATH="/vms/200"
export PVE_ACL_CANARY_UNHELD_ROLE="PVEVMAdmin"
export PVE_ACL_CANARY_TARGET_USER="some-test-user@pve"
```

Optional concurrent issuance load (validated range 1–10; default 10). Lower this
only for a disposable/dev cluster that cannot safely sustain the default user
create/delete load:

```bash
export PVE_CONCURRENT_WORKERS=10
```

Optional TLS settings:

```bash
export PVE_CA_CERT="$(cat /path/to/pve-ca.pem)"
export PVE_TLS_SKIP_VERIFY=false
```

Optional insufficient-privilege canary. If unset, that sub-check is skipped
clearly:

```bash
export PVE_INSUFFICIENT_TOKEN_ID="limited@pve!tokenid"
export PVE_INSUFFICIENT_TOKEN_SECRET="..."
```

Run with:

```bash
make testacc
```

`make testacc` is the canonical operator command. It preflights only the
required variables (`PVE_ADDR`, `PVE_TOKEN_ID`, `PVE_TOKEN_SECRET`,
`PVE_TEST_GROUP`, `PVE_BEHAVIORAL_PATH`, and `PVE_BEHAVIORAL_MARKER`) before
running the verbose, non-cached `TestAcc` suite with `VAULT_ACC=1` and a
30-minute Go test timeout; `PVE_BEHAVIORAL_PATH` must be a group-role-gated
endpoint, not `/version`. Optional variables remain optional. Do not point this
at production unless temporary test users can be safely created, renewed,
expired, and deleted.

## License

This project is licensed under the Mozilla Public License 2.0 — see the [LICENSE](LICENSE) file for details.

---

**Note**: This plugin follows HashiCorp Vault's secrets engine SDK conventions and is intended for use with Proxmox VE's native API token authentication.
