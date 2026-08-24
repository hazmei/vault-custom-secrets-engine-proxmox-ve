# Production Vault Verification Procedure

This procedure is an operator-run verification of the Proxmox VE secrets engine
on a production Vault cluster. It supplements the [README installation
overview](../README.md#build-and-install); it does not replace the
[architecture specification](ARCHITECTURE.md) or the recorded status in the
[implementation plan](IMPLEMENTATION_PLAN.md).

The procedure is intentionally written as a checklist. Record results in the
approved change ticket, but never record credentials, lease token secrets, or
full command output containing them.

## Scope and safety

- Run this only during an approved change window, with Vault and Proxmox
  owners available for rollback and cleanup.
- Use a dedicated production Vault mount and a dedicated, non-human PVE
  provisioner identity. Do not use a human identity, `root@pam`, an acceptance
  identity, or the repository's development server for this verification.
- Use the dedicated PVE verification group `vault-production-readers`, whose
  ACL bindings are explicitly approved for the test. The group must not grant
  more access than the behavioral check requires.
- Treat the PVE provisioner token secret and every issued lease token secret as
  one-time credentials. Put them in the approved secret manager or protected
  operator session; do not put them in shell history, CI logs, tickets, chat,
  screenshots, support bundles, or this repository.
- The concrete verification example below uses the PVE group
  `vault-production-readers`, the delegated PVE role `PVEAuditor`, the target
  realm `<REALM>`, and Vault role `production-readers`. Keep placeholders such as
  `<VAULT_ADDR>`, `<PVE_HOST>`, and provisioner identity values where the
  environment-specific value is genuinely required. Do not substitute real
  secrets into documentation or commit them.
- This procedure creates and deletes PVE users and tokens and mutates Vault
  mount state. Stop if the target is not disposable for the PVE lifecycle
  portion or if cleanup cannot be guaranteed.

This is a verification procedure, not a production-readiness claim. The
repository's prior local `vault server -dev` test does **not** prove production
catalog registration, persistence, HA forwarding, failover recovery, or
filesystem behavior. PVE lifecycle checks still require a safe disposable or
explicitly approved target.

## Prerequisites

### Vault cluster

- A supported Vault release and an operational, initialized, unsealed cluster
  with at least two nodes.
- Administrative access sufficient to configure the plugin catalog, enable the
  mount, create the verification policies, and inspect audit/health results.
- A real filesystem path for `plugin_directory` on **every** Vault node. The
  path must not be a symlink and must be accessible by the Vault service user.
- A backup/snapshot and a tested operator rollback path for the mount and
  catalog entry.
- Vault audit logging enabled through the organization's approved sink, with
  secret values excluded or protected according to policy.

### Build inputs

- The intended commit/tag and a clean, reviewable source checkout.
- Go version and build prerequisites required by the repository. The canonical
  build is `make build`, which writes
  `vault/plugins/vault-plugin-secrets-proxmox`.
- A release artifact transfer process that preserves executable bits and does
  not transform the binary.

### Operator workstation

- `curl` 7.55.0 or newer when using `--header @-` below. On older systems,
  write each header to a mode-0600 temporary file, use `--header @<file>`, and
  securely remove the file after the request.

### Proxmox VE

- A PVE target compatible with the repository's documented target (PVE 9.2.10
  at the time of writing), with approved API/TLS connectivity from each Vault
  node.
- A dedicated provisioner user and token, created by a PVE cluster
  administrator.
- The pre-created verification group `vault-production-readers` and its
  approved group-to-role ACL binding. The engine does not create groups or ACL
  bindings.

### Permission contract and evidence

The following matrix is the acceptance contract for the dedicated provisioner
identity. “Effective” includes an exact-path grant or a propagating grant on
an ancestor. The distinction between the parent and child group paths is
deliberate: PVE checks different paths for different operations.

| Engine operation | PVE calls exercised | Required provisioner permission and path | Verification note |
| --- | --- | --- | --- |
| Config validation | `GET /version`, `GET /access/permissions` | `User.Modify` at `/access/groups`; `Sys.Audit` at `/access/groups` | `/version` proves reachability/TLS only. The permissions tree is parsed and ancestor paths are walked. |
| Role write | `GET /access/groups/{group}`, `GET /access/permissions` | `Sys.Audit` at `/access/groups`; `User.Modify` effective at `/access/groups/<group>`; `Realm.AllocateUser` at `/access/realm/<realm>` | Group existence and the realm are role-specific. The exact child-path check catches a non-propagating parent grant before issuance. |
| Credential create | `POST /access/users` with `groups=<group>`, read-back `GET /access/users/{id}`, then token creation | `User.Modify` effective at `/access/groups/<group>`; `Realm.AllocateUser` at `/access/realm/<realm>` | The child-path `User.Modify` is normally supplied by propagating `/access/groups`. The group must already exist. |
| Renewal | `GET /access/users/{id}`, `PUT /access/users/{id}` with `expire` + `groups` + `enable` + `append=1`, then read-back | `User.Modify` at the parent `/access/groups` | A child-only grant is insufficient. This unavoidable parent check is why the provisioner is not per-group scoped. |
| Revocation | `DELETE /access/users/{id}` | `User.Modify` at the parent `/access/groups` | The delete cascades to the lease token and membership. Missing-user body `"no such user"` is idempotent success. |

`Sys.Audit` is present to support the recommended early group-existence check
(`GET /access/groups/{group}`) during role write. It is not a delegated
credential permission and is not needed to make the issued token powerful.
Operators may omit that precheck, and therefore `Sys.Audit`, only if they
accept discovering a missing group at issuance time instead.

The config write and every role write use `GET /access/permissions` to verify
the effective permission tree. A successful `GET /version` is only a
reachability/authentication and TLS check; it is not permission evidence.
Capture redacted evidence for each target realm and group before proceeding:

- the provisioner identity and the effective `User.Modify` entry at the parent
  `/access/groups`, including its propagation flag;
- the effective `User.Modify` result at
  `/access/groups/vault-production-readers`;
- the effective `Sys.Audit` result at `/access/groups`; and
- the effective `Realm.AllocateUser` result at `/access/realm/<REALM>`.

Evidence should show the relevant path, privilege, and `:0`/`:1` propagation
value from the permissions response or an equivalent redacted administrator
query. Remove token IDs' secrets, Authorization headers, unrelated user data,
and unnecessary cluster details. Keep the evidence in the approved change
record and record which cluster, realm, group, and timestamp it describes.
Do not treat a bare `/version` response, a role definition alone, or the
provisioner's own identity as proof of any item in this checklist.

#### Provisioner versus delegated credentials

The provisioner identity and issued lease identities have different jobs. A
cluster administrator creates `vault-production-readers` and binds it
out-of-band to the approved PVE role(s) and path(s). The engine only creates
synthetic users, adds them to that pre-created group, and creates their
tokens; it does not create groups or ACL bindings and does not grant roles
with `PUT /access/acl`.
Issued credentials therefore need not use roles held by the provisioner. The
provisioner needs the user-management and validation permissions in the
matrix, while a lease token inherits the roles bound to its group with
`privsep=0`.

This is least privilege only relative to a full-admin provisioner. The
required parent-path `User.Modify` is unavoidably cluster-wide user
administration: a compromised provisioner can affect users beyond this mount
and can create a user in any privileged group it can name. Treat the
provisioner token as high-impact, monitor its user/group mutations, and do
not describe this setup as per-group isolation or risk-free least privilege.

## 1. Build and distribute one verified artifact

Confirm the intended absolute `plugin_directory` on every Vault node before
transferring the artifact; step 2 applies that path to the effective Vault
configuration.

Build from the reviewed source revision:

```bash
make build
shasum -a 256 vault/plugins/vault-plugin-secrets-proxmox
```

Build for the Vault server's platform. If the build host differs, cross-compile
with `GOOS=linux GOARCH=arm64 make build`; the SHA-256 below must be the hash of
the artifact that will actually be installed on the Vault node.

Record the commit and SHA-256 digest in the change ticket. Transfer that exact
binary to the approved plugin directory on every Vault node. On each node,
verify the digest independently and verify ownership, mode, and path:

```bash
EXPECTED_SHA="<SHA256_FROM_CHANGE_TICKET>" \
EXPECTED_OWNER="vault:vault" \
VERIFY_PLUGIN_DIR="/etc/vault/plugins" \
make verify-artifact
```

The target is a convenience wrapper for a node that has the repository
checkout and `make`. On hardened nodes without either, stream the standalone
script from the operator workstation and run it directly on the node instead.
This avoids staging the verifier in world-writable `/tmp`:

```bash
verified=1
# Replace these placeholders with every Vault node's hostname or address.
for node in "<VAULT_NODE_1>" "<VAULT_NODE_2>" "<VAULT_NODE_3>"; do
  # Keep the continuation inside the quoted command for the remote shell.
  if ! ssh "$node" 'EXPECTED_SHA="<SHA256_FROM_CHANGE_TICKET>" \
    EXPECTED_OWNER="vault:vault" PLUGIN_DIR=/etc/vault/plugins bash -s' \
    < scripts/verify-plugin-artifact.sh; then
    echo "FAIL: artifact verification failed on $node"
    verified=0
  fi
done
if [ "$verified" -eq 1 ]; then
  echo "PASS: artifact verified on every Vault node"
else
  echo "STOP: do not continue until every Vault node passes verification"
fi
```

The guard reports SSH's non-zero status when verification fails and records the
overall result in `verified`. It continues through the list so one run reports
every failing node. Do not proceed to the next step unless the final message
confirms that every node passed verification.

The loop runs the wrapper or standalone script once per Vault node. Set
`VERIFY_PLUGIN_DIR`/`PLUGIN_DIR` to the node's absolute `plugin_directory`; the
script preflights the GNU command forms it uses, checks the digest, service-user
execution, owner/group, and every ancestor directory, and exits non-zero when
verification fails. `EXPECTED_SHA` and `EXPECTED_OWNER` must be the approved
values from the change ticket and deployment standard.

The ancestor check covers every parent directory up to `/`; stage rehearsals in
a non-world-writable directory, not `/tmp`, or the check will fail on `/tmp`
even when the artifact itself is correct.

On platforms without `sha256sum` or GNU `stat`, adapt the script to use the
platform equivalents (for example, `shasum -a 256` and
`stat -f '%Su:%Sg %Lp'` on BSD/macOS) before running it.
The digest must match on all nodes before registration. If any node differs,
stop and correct distribution; do not register a mixed artifact set.

## 2. Configure `plugin_directory`

Configure the same real directory on every Vault server, for example:

```hcl
plugin_directory = "/etc/vault/plugins"
```

Confirm the effective configuration and restart/reload according to the
cluster's change procedure. After the restart/reload, re-run the verification
loop from section 1 against every node in the same operator shell. It re-checks
the digest, service-user execution, owner/group, symlink status, and write
 permissions on the artifact and its parent directories. Invalidate the
 pre-restart result before restarting, then re-run the loop so its final result
 is the result used by the registration gate below:

```bash
verified=0
```

Do not proceed with catalog registration until all nodes have the same artifact
and directory configuration, and every post-restart verification succeeds.

## 3. Register and enable the plugin

From an approved operator session, register the plugin by catalog name using the
SHA-256 digest recorded in step 1. Run this against the production Vault API;
do not calculate a digest from a workstation-local path:

```bash
export VAULT_ADDR='<VAULT_ADDR>'
# Supply VAULT_TOKEN only through the approved protected session.
if [ "${verified:-0}" -ne 1 ]; then
  echo "STOP: plugin registration requires a passing verification loop"
else
  vault plugin register -sha256="<SHA256_FROM_CHANGE_TICKET>" \
    secret vault-plugin-secrets-proxmox
  vault plugin list secret
  vault secrets enable -path=proxmox vault-plugin-secrets-proxmox
  vault secrets list
fi
```

Run sections 1–3 in the same operator shell, or repeat the section 1 loop in
the shell used for registration so that `verified=1` reflects the latest
post-restart verification.

Confirm that the catalog entry's SHA-256 matches the digest recorded in step 1,
and that the mount is enabled at the intended path. Do not use
`-dev-plugin-dir`: development auto-registration is a different path and is
not evidence of production registration.

## 4. Apply least-privilege Vault policies

Use a narrowly scoped verification operator token. Adapt policy paths to the
chosen mount and the organization's identity model; the example deliberately
contains no token values:

```hcl
path "proxmox/config" {
  capabilities = ["create", "read", "update"]
}

path "proxmox/roles/production-readers" {
  capabilities = ["create", "read", "update", "delete"]
}

path "proxmox/creds/production-readers" {
  capabilities = ["read"]
}

path "sys/leases/renew" {
  capabilities = ["update"]
}

path "sys/leases/revoke" {
  capabilities = ["update"]
}
```

The config delete is intentionally absent from the routine policy. Grant it
only to a separately controlled cleanup operator, or temporarily through the
approved break-glass process. Verify the effective policy before testing:

```bash
vault token capabilities proxmox/config
vault token capabilities proxmox/roles/production-readers
vault token capabilities proxmox/creds/production-readers
vault token capabilities sys/leases/renew
vault token capabilities sys/leases/revoke
```

Expected capabilities are the minimum operations above. `vault token
capabilities` is an authorization check, not a substitute for testing the
actual endpoint behavior. Vault's built-in `default` policy already grants
`sys/leases/renew` and its path form, so this stanza is usually redundant
unless the verification token is created with `-no-default-policy`.

## 5. Prepare the dedicated PVE verification identity

### 5.1 Create and bind the delegated verification group

This step is performed out-of-band by a Proxmox cluster administrator before
the Vault provisioner identity is created. Confirm that `PVEAuditor` is the
intended example role and review its privileges and path scope against the
approved change. `PVEAuditor` is illustrative, not a blanket recommendation;
use the approved delegated role for the target.

```bash
pveum role list
pveum group add vault-production-readers --comment "Vault production read-only lease group"
pveum acl modify /nodes/<NODE> --group vault-production-readers --role PVEAuditor --propagate 1
```

The group ACL is an out-of-band administrator configuration. The engine only
adds each synthetic user to the already-existing group and creates a token
with `privsep=0`; the issued token inherits the group's bound role and path
access. The engine does not create PVE groups or ACL bindings. Rebinding or
removing this group ACL changes the access of outstanding credentials, so
revoke all verification leases before changing or deleting the group or its
binding.

Capture redacted administrator evidence before continuing:

- the existence and comment of `vault-production-readers`;
- the binding of `PVEAuditor` to that group, including the approved path
  `/nodes/<NODE>` and propagation enabled (`1`); and
- the reviewed, approved privilege and path scope of `PVEAuditor`.

Do not include token secrets, Authorization headers, or unrelated cluster data
in the evidence. Keep it in the approved change record and record the cluster,
group, delegated role, scope, and timestamp it describes.

As a PVE cluster administrator, create a dedicated provisioner role/user and
scope it to the target realm and groups path. The `/access/groups` grant must
propagate: creation checks `/access/groups/<group>`, while renewal and revoke
check the parent path.

```bash
pveum user add <PROVISIONER>@<REALM> --comment "Vault production verification"
pveum role add VaultProvisioner \
  --privs "User.Modify Realm.AllocateUser Sys.Audit"
pveum acl modify /access/groups \
  --user <PROVISIONER>@<REALM> --role VaultProvisioner --propagate 1
pveum acl modify /access/realm/<REALM> \
  --user <PROVISIONER>@<REALM> --role VaultProvisioner --propagate 0
# vault-production-readers must already exist and have only the approved
# PVEAuditor role/path binding documented in section 5.1.
pveum user token add <PROVISIONER>@<REALM> vault \
  --privsep 0 --comment "Vault production verification token"
```

The realm ACL is explicitly shown with `--propagate 0`: the required
`Realm.AllocateUser` grant is scoped to the exact `/access/realm/<REALM>` path.
Use `--propagate 1` only when the security review explicitly requires
allocation in child realm paths and the evidence records that broader scope.
In contrast, `--propagate 1` on the `/access/groups` parent is mandatory because
creation checks `/access/groups/<group>` while renewal and revocation check the
parent.

Capture the token secret once into the approved secret manager. `privsep=0` is
mandatory: the default `privsep=1` gives the provisioner token a separate empty
ACL, so the engine's own privilege validation and user-provisioning calls are
denied. The engine separately sets `privsep=0` on each issued lease token so it
inherits the synthetic user's group access.
Verify the `vault-production-readers` binding and propagated `User.Modify` with
the PVE administrator before continuing. The PVE token secret is never read
back by the engine and must not be logged.

## 6. Configure and verify redaction

Write configuration through the protected session. Prefer a trusted CA bundle;
do not use `tls_skip_verify=true` as a production workaround:

```bash
vault write proxmox/config \
  address="https://<PVE_HOST>:8006" \
  token_id="<PROVISIONER>@<REALM>!vault" \
  token_secret=@<PROVISIONER_SECRET_FILE> \
  tls_skip_verify=false ca_cert=@<CA_BUNDLE> \
  default_ttl=3600 default_max_ttl=86400
vault read proxmox/config
```

Create `<PROVISIONER_SECRET_FILE>` without a trailing newline. The Vault CLI
reads `@<file>` contents verbatim; use `printf %s` rather than `echo` when
writing the one-time secret. A trailing newline is harmless in the PEM CA
bundle, but would make the provisioner secret incorrect and lead to a PVE 401.

Confirm the read response contains the address, TLS settings, TTLs, and token
ID, but **does not contain `token_secret`**. Also confirm the secret is absent
from the terminal capture, audit output available to the operator, and change
ticket. The config write performs a behavioral permission check through
`GET /access/permissions`; a successful `/version` reachability check alone is
not sufficient.

## 7. Write a role and issue a credential

Use the pre-created `vault-production-readers` group and finite TTLs:

```bash
vault write proxmox/roles/production-readers \
  group="vault-production-readers" user_prefix="vault" realm="<REALM>" \
  ttl=300 max_ttl=900
vault read proxmox/roles/production-readers
vault read proxmox/creds/production-readers
```

The role write validates that the group exists and that the provisioner has
the required effective permissions for the group child path and
`/access/realm/<REALM>`; a successful write is therefore evidence of those checks,
not just a stored role definition. After issuance, verify in PVE that the
synthetic user belongs to `vault-production-readers` and that its token has
only the reviewed, inherited `PVEAuditor` access at the approved path. Confirm
the behavioral endpoint in section 8 with that credential.

Store the issued `token_secret` only in the approved protected session. Record
the returned PVE user ID for cleanup, but not the secret. Do not treat the
Vault role definition alone as proof of group membership or inherited access.

## 8. Use the credential against a behavioral endpoint

Do not use `/version` as the sole acceptance check: it proves reachability and
authentication, not the group-derived authorization contract. Use an approved
endpoint that is allowed by the PVE role bound to `vault-production-readers`
and returns a stable, non-sensitive marker. For example, substitute the
endpoint and marker
approved for the target:

Use the complete `token_id` returned by the credential response when constructing
the header; do not rebuild it from the user ID, realm, or the engine's current
lease-token constant. Keep both returned values in the approved protected session
only, and never print them.

```bash
# Set TOKEN_ID from token_id and LEASE_SECRET from token_secret in the protected session.
printf 'Authorization: PVEAPIToken=%s=%s\n' "$TOKEN_ID" "$LEASE_SECRET" | \
  curl --fail --silent --show-error \
  --header @- "https://<PVE_HOST>:8006/api2/json/<BEHAVIORAL_PATH>"
```

Confirm HTTP 200 and the approved response marker. Also verify that an endpoint
outside the group's approved access is denied, where the security review has
provided a safe negative check. Never print the Authorization header or save
the response if it contains sensitive data.

## 9. Renew and revoke

Renew through Vault's lease endpoint, using the lease ID returned by the issue
operation:

```bash
vault lease renew -increment=300 <LEASE_ID>
```

Confirm the renewal succeeds, the PVE user's `expire` advances, group
membership remains present, and the behavioral endpoint still succeeds. If the
PVE user is disabled out-of-band, renewal must refuse to silently re-enable it.

Revoke the lease and verify cleanup:

```bash
vault lease revoke <LEASE_ID>
```

Confirm the PVE user and its token are gone. To exercise revoke idempotency,
issue a credential, delete its PVE user out-of-band, confirm the user is
missing, and then revoke that still-active Vault lease. PVE's missing-user
response is HTTP 500 with body `"no such user"`, which the engine treats as
success. Confirm the issued token no longer authenticates.

## 10. Verify config deletion and cleanup

Revoke all verification leases **before** deleting config. A config deletion
removes the admin credential; outstanding PVE users then cannot be renewed or
revoked by the engine. The `force=true` value is plugin data, not the Vault CLI
confirmation flag:

```bash
vault delete proxmox/config force=true
# Or explicitly:
printf 'X-Vault-Token: %s\n' "$BREAK_GLASS_TOKEN" | \
  curl --fail --silent --show-error -X DELETE \
  --header @- "${VAULT_ADDR}/v1/proxmox/config?force=true"
```

Verify that deletion without the data parameter is rejected. After the test,
delete the temporary Vault role/mount and catalog entry according to the
change plan. Complete and record every item in this cleanup checklist:

- revoke every verification lease and confirm its synthetic PVE user and
  `lease` token are gone;
- remove the provisioner API token (`vault` in the example), or record its
  retained owner, purpose, expiry/rotation date, and secret-manager location;
- remove the provisioner user's ACL entries, then delete the dedicated
  provisioner user, or document the approved retained owner and rotation
  schedule;
- remove the temporary `VaultProvisioner` custom role when it is no longer
  referenced, or document why it is retained and who owns its review;
- after all verification leases are revoked, remove the
  `vault-production-readers` group's ACL role bindings and delete the group
  when it is no longer needed, or document its retained ownership, approved
  bindings, and next review/rotation date; and
- remove temporary Vault policies, the mount, and the plugin catalog entry as
  required by the change plan.

Perform PVE cleanup with a cluster administrator and verify the final state
using redacted user, token, group, and ACL listings. If any synthetic user,
token, ACL entry, group, or provisioner object remains, do not mark the
procedure complete: remove it through the approved administrator process or
record the exception, owner, reason, access scope, and rotation/expiry plan in
the change ticket.

## 11. HA, standby, and failover checks

Run these checks with the cluster owners and an approved failure plan:

1. Identify the active and standby nodes. Confirm the enabled mount and plugin
   catalog entry are visible through the cluster API, and that every node has
   the same binary digest.
2. Send config, role, issue, renew, and revoke requests through the normal
   cluster address, not a node-local development address. Confirm mutating
   credential issuance is forwarded to the active node before any PVE call.
   Record the active node from the cluster API and correlate a controlled issue
   with the PVE proxy log; the `POST /api2/json/access/users` source address
   must be the active Vault node, never a standby:

   ```bash
   vault status -format=json | jq -r '.ha_mode, .leader_address'
   # On the PVE host, during the controlled issue:
   grep 'POST /api2/json/access/users' /var/log/pveproxy/access.log | tail -5
   ```

   Use the Vault audit log and the corresponding PVE log entry as the recorded
   evidence for forwarding. This source-address check is conclusive only when
   Vault nodes reach PVE with distinct source addresses; SNAT/NAT gateways,
   shared egress proxies, outbound VIPs, and node-level pod-network
   masquerading can make every node appear identical. When addresses are
   shared, use the file audit device on each Vault node instead: only the node
   that handled the request records the request/response pair for
   `proxmox/creds/production-readers`, while a standby that forwarded the request records
   the request without a backend response. Record the node that produced the
   pair and treat the check as inconclusive if neither source identity nor
   per-node audit evidence is available. Stop if the source address is a
   standby or if the request cannot be correlated.
3. During a controlled active-node failover, verify that an already-issued
   lease can be renewed and revoked through the surviving cluster address.
4. Perform one controlled issue after failover, use its behavioral endpoint,
   renew it, and revoke it. Verify no duplicate/orphan PVE user is left behind.
5. If the Vault version or operational design permits a restart between issue
   and cleanup, verify that the persisted mount, role, lease, catalog entry,
   and WAL-backed lease state are available after restart. Confirm that no
   orphan `vault-*` PVE users remain; this is a read-only check and does not
   require failure injection. Do not simulate a crash in production without an
   approved plan.
6. Review Vault audit logs and PVE audit logs for the expected calls, with no
   token secrets or Authorization headers exposed. Match the issue request to
   the PVE `POST /api2/json/access/users` entry from step 2, and match the
   subsequent token, renewal, and deletion calls to the same lease/user. Record
   the relevant timestamps, node/source identities, HTTP outcomes, and absence
   of secret material; redact token values and Authorization headers from any
   ticket evidence.

Record pass/fail evidence and stop if a standby performs a PVE mutation locally,
the plugin is missing on a node, the digest differs, or cleanup is incomplete.

## Limitations and non-goals

- This document does not certify production readiness, a particular Vault
  version, a PVE cluster configuration, or successful production catalog
  registration. The repository's recorded production-style registration status
  remains unverified until an operator completes this procedure.
- A local `vault server -dev` run with `-dev-plugin-dir` auto-registers plugins
  and does not prove production catalog registration, persistent storage,
  multi-node HA forwarding, failover, or filesystem distribution/permissions.
- PVE lifecycle operations are destructive external mutations. Unit tests and
  local Vault tests do not prove production PVE behavior; use a safe disposable
  or explicitly approved target for issue/use/renew/revoke checks.
- The engine does not create PVE groups or ACL role bindings, rotate the root
  provisioner token automatically, or provide a standalone PVE user-update
  endpoint. Root-token rotation remains manual.
- `force=true` config deletion can strand outstanding PVE users. PVE expiry
  neutralizes an expired credential but does not remove the PVE user record;
  out-of-band cleanup remains the operator's responsibility.
- HA/failover checks here are operational verification steps, not a guarantee
  against every Vault storage, quorum, network, plugin-process, or PVE failure
  mode.
