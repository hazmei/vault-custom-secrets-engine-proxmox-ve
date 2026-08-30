# Proxmox VE Secrets Engine for HashiCorp Vault

A HashiCorp Vault custom secrets engine plugin that issues **dynamic, per-lease Proxmox VE API tokens** with scoped access control and automatic cleanup on revocation.

## Overview

This secrets engine implements Vault's dynamic secrets pattern for Proxmox VE. Each credential lease creates a dedicated, throwaway Proxmox user, adds it to an operator-pre-created PVE group (which the operator has already bound to the desired ACL role(s)), and mints an API token bound to that user. On revocation, a single delete operation removes the user, which cascades to clean up the token, group memberships, and all ACL entries. Orphaned credentials created mid-provision (e.g., from Vault process death or failover) are eventually swept via Vault's Write-Ahead Log (WAL) rollback mechanism.

**Target Platform**: Proxmox VE 9.2.10 for token mode. Password mode is
supported only on the exact verified build
`pve-manager/9.2.14/a1480fa6b8d899cb`; its lifecycle acceptance is complete on
that build. PAM support is explicitly out of scope. Token mode is verified on
both builds.

## Project Status

🚧 **Active implementation** — Core plugin code, unit tests, operator-run live
acceptance tests, and a working `make build` are present. Current Phase 5 and
Phase 6 validation status is tracked in
[`docs/IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md#phased-task-list).

### Recorded Validation

The following validation passed on 2026-08-20 against disposable Proxmox VE
`pve-manager/9.2.10/43df2e01f27a1a19`:

- `make build` completed successfully.
- Vault `server -dev` plugin auto-registration via
  `-dev-plugin-dir=./vault/plugins` and secrets-engine enablement passed.
- The full real-Vault issue → use → renew → revoke lifecycle passed, including
  stored-config validation/redaction, forced config deletion, PVE absence
  verification, and cached-client invalidation.
- The required positive authorization canary passed, including the
  group-role-gated endpoint, expired-user rejection, and renewal group
  preservation checks.

A later run on 2026-08-29 against a disposable
`pve-manager/9.2.14/a1480fa6b8d899cb` target — a different build from the one
above — passed the full required `make testacc` suite plus the opt-in
`TestAccPasswordLifecycle` (password issuance, `POST /access/ticket`
authentication, no API token minted on the user, renewal with the original
password still valid, expiry and disablement rejected with 401, deletion on
revoke), and an operator manual pass through a real `vault server` with
`-dev-plugin-dir`. The same three optional authorization canaries skipped with their
prerequisites unset. The standalone `TestAccPasswordLifecycle` has a separate build
prerequisite and ran because the target was the verified
`pve-manager/9.2.14/a1480fa6b8d899cb` build — a property of the cluster, not an
operator choice. Neither kind of skip is completed coverage. Evidence:
`docs/PVE_PROBES.md`.

Production-style catalog registration with
`vault plugin register -sha256=<hash>` was verified previously (undated) on a
single-node non-dev Vault, including a matching catalog digest and catalog/mount
persistence across a Vault restart. Multi-node artifact distribution,
standby-to-active forwarding, failover, and cross-node restart recovery remain
unverified, so this project must not be treated as production-ready based on the
validation above. Optional insufficient-privilege, direct-ACL, and
negative-authorization canaries were skipped where their separately
documented prerequisites were unset; those skips are not completed coverage. The
standalone password lifecycle test is governed by the separate verified-build condition
above.

The Phase 2 deferred review backlog (DR-1 … DR-6) is fully resolved; no deferred
review items remain. That backlog is independent of the caveats above — it does
not make the project production-ready.

## How It Works

### Credential Lifecycle

1. **Create** (on `GET <mount>/creds/:role`):
   - Creates a synthetic Proxmox user: `{prefix}-{role}-{random}@{realm}` with `groups=<role.group>` at creation time
   - **Token mode** (`mode=token`, the default): mints an API token on the user with `privsep=0` (inherits user ACL) and returns `token_id` + `token_secret` (shown only once, non-reproducible)
   - **Password mode** (`mode=password`): sends an engine-generated password on the same create call and returns `user_id` + `password`. No API token is minted. The password is shown only once and is never rotated (see [Password Mode](#password-mode))

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
| `<mount>/config` | POST, GET, DELETE | Configure Proxmox connection (address, admin token, TLS, default TTLs); GET returns `address`, `tls_skip_verify`, `ca_cert`, `default_ttl`, `default_max_ttl`, `token_id`; `token_secret` never returned; DELETE requires `force=true` as a **data parameter** (not the `vault delete -force` CLI flag — see [Deleting the Configuration](#deleting-the-configuration-forcetrue-is-a-data-parameter-not--force)) — outstanding leases become non-revocable and non-renewable (renewal also loads config to reach PVE, so it fails immediately too; revoke them first) |
| `<mount>/roles/:name` | POST, GET, LIST, DELETE | Define credential roles with group name, TTLs, user prefix, and `mode` (`token` default, or `password`); DELETE does not revoke outstanding leases |
| `<mount>/creds/:role` | GET | Issue a new dynamic credential — token mode returns `user_id`, `token_id`, `token_secret`; password mode returns `user_id`, `password` |
| `<mount>/rotate-root` | POST, GET | Automated crash-recoverable rotation of the dedicated provisioner token; requires `expected_token_id` and `confirm_exclusive=true`; GET reports token-ID-only state |

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

  Rotation also creates a token on the dedicated provisioner user. The
  replacement is accepted only after that create succeeds and its permission
  tree is checked; this repository has no live evidence for a narrower
  token-management ACL path, so verify token creation with the chosen PVE role
  before enabling rotation.
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

### Production Proxmox Prerequisites and Runbook

The following is the production setup path. It is intentionally separate from
the disposable-cluster [acceptance test setup](#acceptance-test-prerequisites),
which uses `vault-acc@pve` and test-only groups. Do not reuse the acceptance
identity, a human identity, or `root@pam` for a production mount.

Before starting this runbook, build and install the plugin and enable the
`proxmox` mount as described in [Build and Install](#build-and-install). The
configuration command in step 4 assumes that the mount already exists.

#### 1. Create a dedicated provisioner identity

Run these commands as a Proxmox cluster administrator. Substitute the target
realm and group names for your environment; do not put a token secret in this
file, shell history, logs, tickets, or chat.

```bash
# Dedicated non-human identity used only by this Vault mount.
pveum user add vault-provisioner@pve --comment "Vault Proxmox provisioner"

# The role contains only the privileges required by the engine.
pveum role add VaultProvisioner \
  --privs "User.Modify Realm.AllocateUser Sys.Audit"

# User.Modify and Sys.Audit are required at the parent groups path.
# Propagation is mandatory: creation checks /access/groups/<group>.
pveum acl modify /access/groups \
  --user vault-provisioner@pve \
  --role VaultProvisioner \
  --propagate 1

# Realm allocation is scoped to the realm used by Vault roles.
pveum acl modify /access/realm/pve \
  --user vault-provisioner@pve \
  --role VaultProvisioner \
  --propagate 1
```

The required privilege paths are exact:

- `User.Modify` on `/access/groups` (parent path), with propagation enabled.
  Creation effectively checks `/access/groups/<group>`; renewal and revocation
  check the parent path. A non-propagating grant (`--propagate 0`) is an invalid
  partial setup: renewal and revocation may work while issuance fails with 403.
- `Sys.Audit` on `/access/groups` for role-write group-existence validation.
- `Realm.AllocateUser` on `/access/realm/<realm>`, validated for each Vault role.

#### 2. Pre-create groups and bind their roles

The engine does not create groups or ACL bindings. A cluster administrator must
create each target group and bind it to the intended PVE role(s) at the intended
path(s) before the corresponding Vault role is written. Prefer one PVE group per
Vault role/use case; changing a group's bindings changes the effective access of
all outstanding credentials in that group immediately.

```bash
pveum group add vault-production-readers \
  --comment "Vault production read-only lease group"

# Example only: choose the role and ACL path appropriate for your policy.
pveum acl modify / \
  --group vault-production-readers \
  --role PVEAuditor \
  --propagate 1
```

The example binding is illustrative, not a claim about the correct production
authorization for every cluster. Confirm the desired role/path with your PVE
administrators and security review. Then configure a Vault role using the
already-existing group; role writes validate group existence and the realm
allocation privilege.

For a starting set of group/binding/role triples covering common access
patterns — read-only auditing, VM operation, VM administration, backup jobs,
and image pipelines — see
[docs/RECOMMENDED_ROLES.md](docs/RECOMMENDED_ROLES.md). Those are starting
points to adapt, subject to the same review as the example above.

#### 3. Create the provisioner API token

The token may be created after the dedicated user exists; before issuing a
credential, ensure the ACL grants, target groups, and Vault role are in place.
**`privsep=0` is mandatory.** Without it, Proxmox's default `privsep=1` gives
the token a separate empty ACL and the engine cannot provision usable
credentials.

```bash
pveum user token add vault-provisioner@pve vault \
  --privsep 0 \
  --comment "Vault production provisioner token"
```

The initial provisioner token must use this same `privsep=0` setting. Rotation
creates replacements with `privsep=0`, which makes them inherit the
provisioner user's ACL. If the initial token used `privsep=1`, its separate
token ACL may differ from the user's ACL, so successful use of the old token
does not prove that a replacement can continue operating.

Proxmox prints the token secret only once. Capture the complete one-time secret
directly into an approved secret manager or protected operator session. The
provisioner token is the **engine's administrative credential** and is distinct
from generated lease credentials:

- Provisioner token: configured at `<mount>/config`; it creates, renews, and
  revokes synthetic users and must never be issued to workloads.
- Lease token: returned by `<mount>/creds/:role`; it belongs to one disposable
  user, has the target group's effective access, and is revoked with that user.

The token ID (`vault-provisioner@pve!vault`) is not secret; the token secret is.
Do not expose the secret in command output captures, CI logs, shell history,
support bundles, issues, pull requests, or documentation.

#### 4. Configure and verify the production mount

Use the protected secret when writing the mount configuration. Prefer a trusted
CA bundle over `tls_skip_verify=true`. If creating the secret file from a shell
variable, read it without echoing or placing it in shell history, create a
file readable only by the operator, and preserve the secret without a trailing
newline:

```bash
read -rs SECRET   # paste the one-time secret; not echoed, not in history
install -d -m 0700 /run/secrets
install -m 0600 /dev/null /run/secrets/pve-provisioner-token
printf '%s' "$SECRET" > /run/secrets/pve-provisioner-token
```

Then write the mount configuration and a role:

```bash
vault write proxmox/config \
  address="https://pve.example.com:8006" \
  token_id="vault-provisioner@pve!vault" \
  token_secret=@/run/secrets/pve-provisioner-token \
  tls_skip_verify=false \
  ca_cert=@/path/to/pve-ca.pem \
  default_ttl=3600 \
  default_max_ttl=86400

vault write proxmox/roles/production-readers \
  group="vault-production-readers" \
  user_prefix="vault" \
  realm="pve" \
  ttl=3600 \
  max_ttl=86400

unset SECRET
rm -f /run/secrets/pve-provisioner-token
```

The config write checks connectivity and the provisioner's permissions; the
role write checks the target group, realm allocation, and effective propagated
`User.Modify` at the per-group path. Issue a test lease only after reviewing
the returned group's authorization, then revoke it and confirm the temporary
PVE user is gone. Keep production issuance and revocation monitoring in the
normal Vault/PVE change and audit process.

#### 5. Rotate the provisioner token safely

Rotate the dedicated provisioner token through Vault (shared tokens are unsupported):

```bash
vault write proxmox/rotate-root expected_token_id='vault-admin@pve!root-token' confirm_exclusive=true
```

The response contains only replacement token ID and status. The generated
secret remains in seal-wrapped config and is never returned or written to
rotation metadata, WAL, logs, or errors. A durable recovery record retries
ambiguous cleanup automatically.

If GET reports `recovery-required` and automatic WAL recovery is not making
progress, use the guarded recovery operation below. First copy the exact
`old_token_id` and `new_token_id` from GET, and confirm the active configured
token ID with GET on `config`. Then submit **the exact token ID recorded in the
rotation state**; the engine verifies that the token exists before deleting it
and verifies absence afterward:

```bash
vault write proxmox/rotate-root \
  expected_token_id='CURRENT_CONFIG_TOKEN_ID' \
  confirm_exclusive=true \
  recovery_token_id='EXACT_OLD_OR_NEW_TOKEN_ID_FROM_STATUS'
```

The operation refuses to delete the active configured token, refuses IDs not
recorded in durable rotation state, and fails without clearing state when
absence cannot be confirmed. There is no force-clear operation. Do not edit
Vault storage or manually replace config while rotation state is present.

If config names neither recorded token, automatic rollback intentionally leaves
both tokens and the WAL/state untouched because it cannot safely choose one.
The guarded procedure is exact and status-driven: copy the configured token,
`old_token_id`, and `new_token_id` from status, pass the configured value as
`expected_token_id`, and pass exactly one recorded value as
`recovery_token_id`. The engine verifies existence, deletes only that token,
confirms absence, deletes its recorded WAL, and clears state. It never accepts
a hand-made ID, deletes the active token, exposes a secret, or force-clears
state. If both recorded tokens need cleanup, repeat only after a fresh status
read confirms the pending state remains.

If `rotate-root` reports another rotation, GET distinguishes `in-progress`
(the durable state is recent and may still be active) from
`recovery-required` (config changed, cleanup/confirmation needs recovery, or
the state is stale). Legacy state without a timestamp is treated
conservatively as recovery-required. Allow the automatic WAL rollback manager
to retry before using the guarded operation. The retry timing is governed by
`WALRollbackMinAge` (5 minutes by default) plus rollback retries. Do not retry
with a different expected token or edit Vault storage.
Rotation requires the same propagating `/access/groups`
`User.Modify`, `/access/groups` `Sys.Audit`, and each stored role realm's
`Realm.AllocateUser` privileges as issuance, plus usable token-management
permission on the provisioner user. Token-list permission is also required:
rotation validates it before persisting replacement config and uses it for both
pre- and post-delete `TokenExists` checks. If the configured current token is
already absent, rotation fails closed, retains its recovery state, and reports
an actionable `recovery-required` status; restore the token or use guarded
recovery rather than silently replacing it.

Changing or deleting the configured provisioner token can strand outstanding
leases: their PVE users and lease tokens remain on the cluster, but the engine
may no longer be able to renew or revoke them. Revoke outstanding leases before
rotation where possible, and retain an approved recovery procedure for manual
cleanup. Similarly, do not delete the mount configuration while leases remain;
`DELETE <mount>/config` requires `force=true` and makes those leases
non-renewable and non-revocable by the engine. Note that `force=true` is a data
parameter and the `vault delete -force` CLI flag does not satisfy it — see
[Deleting the Configuration](#deleting-the-configuration-forcetrue-is-a-data-parameter-not--force).

#### Provisioner token blast radius

The required `/access/groups` grant is intentionally cluster-wide user
administration. A compromised provisioner token can modify or delete arbitrary
PVE users and can create a new user in any privileged group, reaching the
privilege ceiling of roles bound to groups. This is not true least privilege in
the compromise case; see the [full threat model](docs/ARCHITECTURE.md#threat-model-admin-token-compromise)
and apply containment controls such as network restriction, token protection,
short finite TTLs, alerting, and regular audit review.

#### Production userid length budget

The generated PVE userid is `{user_prefix}-{role}-{random}@{realm}` and must be
at most 64 characters, including the realm. The role write validates this
budget before issuance:

```text
len(user_prefix) + 1 + len(role) + 1 + 8 + 1 + len(realm) <= 64
```

For example, `vault` / `production-readers` / `pve` uses 37 characters. Choose
the `user_prefix` and Vault role name with this limit in mind so validation does
not fail after the Proxmox setup is complete.

## Build and Install

Build the plugin binary into `vault/plugins/`:

```bash
make build
# Record this digest in the change ticket; use it as <SHA256_FROM_CHANGE_TICKET> below.
shasum -a 256 vault/plugins/vault-plugin-secrets-proxmox
```

### Released binaries

Pre-built binaries for `darwin/arm64`, `darwin/amd64`, `linux/arm64`,
`linux/amd64`, `windows/arm64`, and `windows/amd64` are published by the
manually triggered `Release` workflow (`.github/workflows/release.yml`) and
attached to the corresponding GitHub release, along with `SHA256SUMS` and a
machine-readable `manifest.json`. Each recorded digest is the digest of the raw
binary, so it is directly usable as `<SHA256_FROM_CHANGE_TICKET>` below, as the
`-sha256` argument to `vault plugin register`, and as `EXPECTED_SHA` for
`scripts/verify-plugin-artifact.sh`. Renaming the downloaded file to
`vault-plugin-secrets-proxmox` on install does not change the digest.

Every released binary carries a SLSA build-provenance attestation. Verify both
the provenance and the digest before distributing an artifact to Vault nodes:

```bash
gh attestation verify vault-plugin-secrets-proxmox_<version>_linux_amd64 \
  --repo hazmei/vault-custom-secrets-engine-proxmox-ve

# Linux (GNU coreutils):
sha256sum -c SHA256SUMS --ignore-missing
# macOS, and anywhere else without GNU coreutils:
shasum -a 256 -c SHA256SUMS --ignore-missing
```

`--ignore-missing` checks only the artifacts actually present, so a single
downloaded binary verifies without the other five. The `shasum` substitution is
the same one `scripts/verify-plugin-artifact.sh` names when `sha256sum` is
unavailable; releases include darwin binaries, so operators verifying on macOS
need it.

Releases do not change the project's validation status: production-style
catalog registration with `vault plugin register -sha256=<hash>` is verified for
a single-node non-dev Vault only, the multi-node and HA gates remain unverified,
and releases are marked as pre-releases by default.

For local development, start Vault with the plugin directory. Vault
auto-registers binaries found there, so no manual registration command is
needed in this mode:

```bash
vault server -dev -dev-root-token-id=root -dev-plugin-dir=./vault/plugins
```

The development server is now running with the plugin auto-registered. In a
second terminal, enable the engine at the mount path used by the examples
below:

```bash
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='root'
vault secrets enable -path=proxmox vault-plugin-secrets-proxmox
```

**Production installation (distinct from the development server above):**

For the focused operator checklist covering artifact distribution, production
catalog registration, least-privilege policies, lifecycle verification, and
HA/failover checks, see the [Production Vault Verification
Procedure](docs/PRODUCTION_VERIFICATION.md).

For a production-style install, configure Vault with a real plugin directory,
distribute the binary to every node, verify each node against the SHA-256 digest
recorded at build time (`<SHA256_FROM_CHANGE_TICKET>` below — the value captured
in the change ticket), and only then register it in the Vault plugin catalog.
Put the following stanza in the Vault server configuration file (for example,
`/etc/vault.d/vault.hcl`), then restart Vault for the setting to take effect.
The directory must be configured as a real directory, not a symlink:

```hcl
plugin_directory = "/etc/vault/plugins"
```

From the operator workstation, distribute the built binary and verifier to
each Vault node, then verify every node before registering the plugin:

```bash
# Replace the node placeholders with every Vault node's hostname or address.
verified=1
for node in "<node1>" "<node2>" "<node3>"; do
  if ! scp vault/plugins/vault-plugin-secrets-proxmox "$node":/tmp/; then
    echo "FAIL: could not distribute plugin to $node"
    verified=0
    break
  fi
  # The SSH account must have non-interactive sudo permission for this
  # install command (for example, a narrowly scoped NOPASSWD rule).
  if ! ssh -n "$node" 'sudo -n install -m 0755 \
    /tmp/vault-plugin-secrets-proxmox /etc/vault/plugins/ && \
    rm -f /tmp/vault-plugin-secrets-proxmox'; then
    echo "FAIL: could not install plugin on $node"
    verified=0
    break
  fi
  # Stream the verifier instead of staging it in world-writable /tmp. Use the
  # digest recorded at build time, not one calculated from a local file.
  if ! ssh "$node" 'EXPECTED_SHA="<SHA256_FROM_CHANGE_TICKET>" \
    EXPECTED_OWNER="vault:vault" PLUGIN_DIR=/etc/vault/plugins bash -s' \
    < scripts/verify-plugin-artifact.sh; then
    echo "FAIL: artifact verification failed on $node"
    verified=0
    break
  fi
done
if [ "$verified" -eq 1 ]; then
  # Against the target Vault server configured by VAULT_ADDR:
  vault plugin register -sha256="<SHA256_FROM_CHANGE_TICKET>" \
    secret vault-plugin-secrets-proxmox
  vault secrets enable -path=proxmox vault-plugin-secrets-proxmox
else
  echo "STOP: plugin registration was not attempted"
fi
```

For this production-style path, provide `VAULT_ADDR` and an authenticated
`VAULT_TOKEN` for the target Vault server before running the CLI commands.

The production catalog registration path was live-verified previously (undated)
on a single-node non-dev Vault: the catalog entry's digest matched the recorded
artifact digest, and the catalog entry and mount persisted across a Vault
restart. The commands above are not evidence of multi-node artifact
distribution, standby-to-active forwarding, failover, or cross-node restart
recovery, which remain unverified.

## Configuration Example

```bash
# Configure the secrets engine
vault write proxmox/config \
  address="https://pve.example.com:8006" \
  token_id="vault-admin@pve!root-token" \
  token_secret="<uuid-secret>" \
  tls_skip_verify=false \
  ca_cert=@ca-bundle.pem \
  default_ttl=3600 \
  default_max_ttl=86400
```

The example intentionally uses a placeholder for the one-time token secret.
Keep real token secrets out of shell history, logs, issues, and documentation.

### Deleting the Configuration (`force=true` is a data parameter, not `-force`)

`DELETE <mount>/config` always requires `force=true`. The engine cannot reliably
track outstanding leases, so `force=true` is the explicit operator
acknowledgement that any leases still outstanding become non-revocable and
non-renewable once the admin credential is gone. Revoke outstanding leases
first.

> **Watch out:** `vault delete -force` is a Vault **CLI flag** that only skips
> the interactive confirmation prompt. It sends **no** `force` value to the
> plugin, so `vault delete -force proxmox/config` is still rejected with
> `requires force=true`. The `force` here is a **data parameter** and must be
> passed as a `K=V` pair.

```bash
# Correct — data parameter (Vault CLI >= 1.11 sends K=V pairs on DELETE
# as query parameters)
vault delete proxmox/config force=true

# Correct — explicit query parameter, works with any CLI version
curl -sS -X DELETE -H "X-Vault-Token: $VAULT_TOKEN" \
  "$VAULT_ADDR/v1/proxmox/config?force=true"

# WRONG — `-force` is the CLI's skip-confirmation flag, not this parameter.
# This is rejected with "DELETE <mount>/config requires force=true".
vault delete -force proxmox/config
```

## Role and Usage Example

```bash
# Create a role for VM administrators
# (Assumes a PVE group "vault-vm-admins" already exists and is bound to PVEVMAdmin at /vms/100)
vault write proxmox/roles/vm-admin \
  group="vault-vm-admins" \
  user_prefix="vault" \
  realm="pve" \
  ttl=3600 \
  max_ttl=86400

# Issue a credential
vault read proxmox/creds/vm-admin
# Returns: user_id, token_id, token_secret (lease auto-revokes on expiry)
```

### Password Mode

A role with `mode=password` issues a password on the synthetic PVE user instead
of an API token:

```bash
vault write proxmox/roles/vm-admin-pw \
  group="vault-vm-admins" \
  user_prefix="vault" \
  realm="pve" \
  mode="password" \
  ttl=3600 \
  max_ttl=86400

vault read proxmox/creds/vm-admin-pw
# Returns: user_id, password (lease auto-revokes on expiry)
```

Use `user_id` as the username and `password` as the password against
`POST /access/ticket`, the PVE web UI, or any client that authenticates with a
PVE ticket. The credential inherits the group-derived role exactly as a token
credential does.

Operator notes:

- **Password mode is gated to the exact `pve-manager/9.2.14/a1480fa6b8d899cb`
  build, the only verified build.** The project's token-mode target is 9.2.10,
  whose probe evidence predates password mode and contains no password results.
  The engine enforces this rather than merely warning:
  OPTING IN to `mode=password` is REFUSED unless `GET /version` reports exactly
  `version=9.2.14` and `repoid=a1480fa6b8d899cb`, and `creds/:role` re-checks the
  live build at every issuance and refuses there too (the cluster can be upgraded
  after the role is written). A role write on the verified build still returns a
  warning describing the narrow verification record. **Editing an existing
  password role, renewal, and revocation are NOT gated** — upgrading the cluster
  breaks new password issuance and new opt-ins, but leases already issued keep
  renewing and revoking, and you can still shrink a `ttl`, repoint a `group`, or
  otherwise wind an existing password role down. Verify issuance,
  authentication, renewal, and revocation on your own cluster before relying on
  it — `TestAccPasswordLifecycle` (`VAULT_ACC=1` plus `PVE_PASSWORD_ACC=1`) does
  exactly that.
- **`mode=password` requires `realm=pve`.** Role writes for any other realm,
  including PAM, are refused. PVE-realm password behavior and lifecycle
  acceptance are confirmed live (`docs/PVE_PROBES.md` Probe P0). Historical PAM
  probe results are preserved there as non-blocking evidence only.
- **No API token is minted.** Nothing in the response can be used as
  `PVEAPIToken=`.
- **The password is returned once and is never rotated.** The engine cannot
  rotate it: `PUT /access/password` requires a password-authenticated ticket that
  API-token authentication cannot obtain. To get a new password, revoke the lease
  and read `creds/:role` again.
- **Renewal extends the PVE expiry only** and leaves the original password valid;
  a renewal response never contains a password.
- **Revocation deletes the user**, which invalidates the password immediately.
  Disabling the user out-of-band (`enable=0`) also rejects authentication and
  makes the engine refuse renewal — the operator kill switch works identically to
  token mode.
- **Where the password is stored**: never in this engine's logs, errors, WAL, or
  storage. It IS in Vault core's encrypted lease entry, because Vault persists
  the returned response — factor that into lease retention and audit policy.
- **Do not hand-edit the `comment` field on `vault-*` users.** In password mode a
  comment that no longer matches the WAL nonce is fatal: the engine deletes the
  user and fails issuance rather than return a credential whose crash-recovery
  path is broken. If cleanup itself fails at that point, the user persists until
  its PVE `expire` backstop or manual removal.

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

- **[docs/RECOMMENDED_ROLES.md](docs/RECOMMENDED_ROLES.md)** — A starter set of
  roles for first-time setup: the PVE group and ACL bindings behind each one,
  suggested TTLs, per-team scoping, and the userid length budget

- **[docs/PRODUCTION_VERIFICATION.md](docs/PRODUCTION_VERIFICATION.md)** — The
  production verification procedure for artifact integrity, catalog
  registration, Vault policy checks, PVE-backed lifecycle checks, cleanup, and
  HA/failover validation

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
- Password lifecycle (`TestAccPasswordLifecycle`, opt-in): gated by `VAULT_ACC=1` **plus** `PVE_PASSWORD_ACC=1`, because it creates a password-authenticating PVE user on the target. It additionally skips when the target is not the verified `pve-manager/9.2.14/a1480fa6b8d899cb` build, a cluster property rather than an operator choice. Covers issuance, `POST /access/ticket` authentication, confirmed absence of any API token on the user, renewal with the ORIGINAL password still valid, the past-`expire` 401 backstop, disablement 401, and deletion on revoke. It reports HTTP status codes only and never prints a password. Neither an unset opt-in nor a non-verified build is completed coverage.
- Dedicated provisioner rotation (`TestAccRotateRoot`, opt-in): gated by `VAULT_ACC=1` plus `PVE_ROTATE_ROOT_ACC=1`. It runs the token-mode rotation path against an operator-provided disposable cluster and has not been run as part of this change. Password lifecycle evidence is a separate test and is limited to the verified `pve-manager/9.2.14/a1480fa6b8d899cb` build; PAM remains explicitly out of scope.
- Failure coverage: idempotent revocation after an issued PVE user is deleted out-of-band, WAL rollback, delete-config guard, configurable concurrent issuance, and optional insufficient-privilege config validation in `TestAccInsufficientPrivileges`.
- Unit tests cover deterministic mid-provisioning network/error injection and WAL-delete failure paths. The live acceptance suite does not inject network failures, quorum loss, or ACL lock contention.
- Run against an operator-provided disposable/dev Proxmox VE 9.2.10 cluster with a test admin token. These tests mutate the cluster by creating, renewing, expiring, and deleting temporary `vaultacc-*@pve` users.
- Live acceptance tests are operator-run only and are never run by CI. Normal PR CI runs build, unit tests, and lint only.
- Current recorded operator results and the only optional `TestAcc*` gates that
  may skip are tracked in `docs/IMPLEMENTATION_PLAN.md`; the authorization canary's
  optional subtests and the standalone password lifecycle gate are separate.

#### Acceptance Test Prerequisites

The root `acceptance_test.go` suite mutates a live Proxmox VE cluster. Run it
only against a disposable/dev cluster or a production-like cluster where
temporary `vaultacc-*@pve` users can be safely created, expired, renewed, and
deleted. The suite targets the PVE 9.2.10 behavior documented in
`docs/PVE_PROBES.md`.

This is an acceptance-only setup and is not a production runbook. For
production, use the dedicated `vault-provisioner@pve` identity and the
production procedure above; the acceptance identity and `vault-test-grp` must
not be reused for production workloads.

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

Optional password-mode live coverage. Unset means `TestAccPasswordLifecycle` skips; a
non-verified target also skips because password behavior is only verified on
`pve-manager/9.2.14/a1480fa6b8d899cb`. Set it only on a target where creating a
password-authenticating user is acceptable:

```bash
export PVE_PASSWORD_ACC=1
```

Optional destructive provisioner rotation. Set this only on a disposable/dev
cluster. The test uses a separate bootstrap token to create a disposable
provisioner user, then rotates only that user's token. It never rotates or
deletes `PVE_TOKEN_ID`. The bootstrap token must be separate and remain usable
throughout cleanup:

```bash
export PVE_ROTATE_ROOT_ACC=1
export PVE_ROTATE_BOOTSTRAP_TOKEN_ID="bootstrap-admin@pve!acceptance-bootstrap"
export PVE_ROTATE_BOOTSTRAP_TOKEN_SECRET="<one-time-bootstrap-secret>"
export PVE_ROTATE_PROVISIONER_GROUP="vault-acc-provisioner-grp"
```

`PVE_ROTATE_PROVISIONER_GROUP` must already exist and be bound to the
provisioner privileges required by the engine. These three variables are
required by `make testacc` only when `PVE_ROTATE_ROOT_ACC=1`.

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
