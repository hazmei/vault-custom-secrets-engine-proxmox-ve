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
- Use a dedicated PVE verification group whose ACL bindings are explicitly
  approved for the test. The group must not grant more access than the
  behavioral check requires.
- Treat the PVE provisioner token secret and every issued lease token secret as
  one-time credentials. Put them in the approved secret manager or protected
  operator session; do not put them in shell history, CI logs, tickets, chat,
  screenshots, support bundles, or this repository.
- Use placeholders such as `<VAULT_ADDR>`, `<MOUNT>`, and `<PVE_GROUP>` below.
  Do not substitute real secrets into documentation or commit them.
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

### Proxmox VE

- A PVE target compatible with the repository's documented target (PVE 9.2.10
  at the time of writing), with approved API/TLS connectivity from each Vault
  node.
- A dedicated provisioner user and token, created by a PVE cluster
  administrator.
- A pre-created verification group and approved group-to-role ACL binding.
  The engine does not create groups or ACL bindings.

## 1. Build and distribute one verified artifact

Build from the reviewed source revision:

```bash
make build
shasum -a 256 vault/plugins/vault-plugin-secrets-proxmox
```

Record the commit and SHA-256 digest in the change ticket. Transfer that exact
binary to the approved plugin directory on every Vault node. On each node,
verify the digest independently and verify ownership, mode, and path:

```bash
sha256sum /etc/vault/plugins/vault-plugin-secrets-proxmox
test -x /etc/vault/plugins/vault-plugin-secrets-proxmox
# Verify the Vault service user can execute it, the expected owner/group are set,
# and no group or other write permission is present. Use the platform-equivalent
# stat/find commands where these GNU options are unavailable.
test -z "$(find /etc/vault/plugins/vault-plugin-secrets-proxmox \
  -perm /022 -print -quit)"
```

On platforms without `sha256sum` or GNU `stat`, use the platform equivalents.
The digest must match on all nodes before registration. If any node differs,
stop and correct distribution; do not register a mixed artifact set.

## 2. Configure `plugin_directory`

Configure the same real directory on every Vault server, for example:

```hcl
plugin_directory = "/etc/vault/plugins"
```

Confirm the effective configuration and restart/reload according to the
cluster's change procedure. Verify on every node that:

1. the directory exists and is not a symlink;
2. the Vault service user can execute the binary;
3. the verified digest is unchanged; and
4. file permissions do not expose the artifact for unauthorized replacement.

Do not proceed with catalog registration until all nodes have the same artifact
and directory configuration.

## 3. Register and enable the plugin

From an approved operator session, register the plugin by catalog name using the
SHA-256 digest recorded in step 1. Run this against the production Vault API;
do not calculate a digest from a workstation-local path:

```bash
export VAULT_ADDR='<VAULT_ADDR>'
# Supply VAULT_TOKEN only through the approved protected session.
vault plugin register -sha256="<SHA256_FROM_CHANGE_TICKET>" \
  secret vault-plugin-secrets-proxmox
vault plugin list secret
vault secrets enable -path=<MOUNT> vault-plugin-secrets-proxmox
vault secrets list
```

Confirm that the catalog entry's SHA-256 matches the digest recorded in step 1,
and that the mount is enabled at the intended path. Do not use
`-dev-plugin-dir`: development auto-registration is a different path and is
not evidence of production registration.

## 4. Apply least-privilege Vault policies

Use a narrowly scoped verification operator token. Adapt policy paths to the
chosen mount and the organization's identity model; the example deliberately
contains no token values:

```hcl
path "<MOUNT>/config" {
  capabilities = ["create", "read", "update"]
}

path "<MOUNT>/roles/<ROLE>" {
  capabilities = ["create", "read", "update", "delete"]
}

path "<MOUNT>/creds/<ROLE>" {
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
vault token capabilities <MOUNT>/config
vault token capabilities <MOUNT>/roles/<ROLE>
vault token capabilities <MOUNT>/creds/<ROLE>
vault token capabilities sys/leases/renew
vault token capabilities sys/leases/revoke
```

Expected capabilities are the minimum operations above. `vault token
capabilities` is an authorization check, not a substitute for testing the
actual endpoint behavior. Vault's built-in `default` policy already grants
`sys/leases/renew` and its path form, so this stanza is usually redundant
unless the verification token is created with `-no-default-policy`.

## 5. Prepare the dedicated PVE verification identity

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
  --user <PROVISIONER>@<REALM> --role VaultProvisioner --propagate 1
# <PVE_GROUP> must already exist and have only the approved role/path binding.
pveum user token add <PROVISIONER>@<REALM> vault \
  --privsep 0 --comment "Vault production verification token"
```

Capture the token secret once into the approved secret manager. `privsep=0` is
mandatory: the default `privsep=1` gives the provisioner token a separate empty
ACL, so the engine's own privilege validation and user-provisioning calls are
denied. The engine separately sets `privsep=0` on each issued lease token so it
inherits the synthetic user's group access.
Verify the group binding and propagated `User.Modify` with the PVE
administrator before continuing. The PVE token secret is never read back by
the engine and must not be logged.

## 6. Configure and verify redaction

Write configuration through the protected session. Prefer a trusted CA bundle;
do not use `tls_skip_verify=true` as a production workaround:

```bash
vault write <MOUNT>/config \
  address="https://<PVE_HOST>:8006" \
  token_id="<PROVISIONER>@<REALM>!vault" \
  token_secret=@<PROVISIONER_SECRET_FILE> \
  tls_skip_verify=false ca_cert=@<CA_BUNDLE> \
  default_ttl=3600 default_max_ttl=86400
vault read <MOUNT>/config
```

Confirm the read response contains the address, TLS settings, TTLs, and token
ID, but **does not contain `token_secret`**. Also confirm the secret is absent
from the terminal capture, audit output available to the operator, and change
ticket. The config write performs a behavioral permission check through
`GET /access/permissions`; a successful `/version` reachability check alone is
not sufficient.

## 7. Write a role and issue a credential

Use the pre-created verification group and finite TTLs:

```bash
vault write <MOUNT>/roles/<ROLE> \
  group="<PVE_GROUP>" user_prefix="vault" realm="<REALM>" \
  ttl=300 max_ttl=900
vault read <MOUNT>/roles/<ROLE>
vault read <MOUNT>/creds/<ROLE>
```

Store the issued `token_secret` only in the approved protected session. Record
the returned PVE user ID for cleanup, but not the secret. Confirm in PVE that
the synthetic user is a member of `<PVE_GROUP>` and that its token was created
with the expected inherited access.

## 8. Use the credential against a behavioral endpoint

Do not use `/version` as the sole acceptance check: it proves reachability and
authentication, not the group-derived authorization contract. Use an approved
endpoint that is allowed by the verification group's PVE role and returns a
stable, non-sensitive marker. For example, substitute the endpoint and marker
approved for the target:

```bash
printf 'Authorization: PVEAPIToken=%s@%s!lease=%s\n' \
  "$ISSUED_USER" "$REALM" "$LEASE_SECRET" | \
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

Confirm the PVE user and its token are gone. Repeat the revoke (or revoke after
out-of-band deletion) and confirm it succeeds idempotently: PVE's missing-user
response is HTTP 500 with body `"no such user"`, which the engine treats as
success. Confirm the issued token no longer authenticates.

## 10. Verify config deletion and cleanup

Revoke all verification leases **before** deleting config. A config deletion
removes the admin credential; outstanding PVE users then cannot be renewed or
revoked by the engine. The `force=true` value is plugin data, not the Vault CLI
confirmation flag:

```bash
vault delete <MOUNT>/config force=true
# Or explicitly:
printf 'X-Vault-Token: %s\n' "$BREAK_GLASS_TOKEN" | \
  curl --fail --silent --show-error -X DELETE \
  --header @- "${VAULT_ADDR}/v1/<MOUNT>/config?force=true"
```

Verify that deletion without the data parameter is rejected. After the test,
delete the temporary Vault role/mount and catalog entry according to the
change plan, remove the provisioner token and verification group/bindings,
and confirm no synthetic PVE users remain. If any user remains, revoke it
through the approved PVE administrator process and document the reason.

## 11. HA, standby, and failover checks

Run these checks with the cluster owners and an approved failure plan:

1. Identify the active and standby nodes. Confirm the enabled mount and plugin
   catalog entry are visible through the cluster API, and that every node has
   the same binary digest.
2. Send config, role, issue, renew, and revoke requests through the normal
   cluster address, not a node-local development address. Confirm mutating
   credential issuance is forwarded to the active node before any PVE call.
3. During a controlled active-node failover, verify that an already-issued
   lease can be renewed and revoked through the surviving cluster address.
4. Perform one controlled issue after failover, use its behavioral endpoint,
   renew it, and revoke it. Verify no duplicate/orphan PVE user is left behind.
5. If the Vault version or operational design permits a restart between issue
   and cleanup, verify that the persisted mount, role, lease, catalog entry,
   and WAL rollback behavior are available after restart. Do not simulate a
   crash in production without an approved plan.
6. Review Vault audit logs and PVE audit logs for the expected calls, with no
   token secrets or Authorization headers exposed.

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
