# Recommended Starter Roles

A starting point for operators standing up this engine for the first time. The
set below is intentionally small and covers the most common Proxmox VE access
patterns. Extend it with cluster-specific roles as needed — nothing here is
built into the engine, and adding a role is a `pveum` binding plus a
`vault write`.

**These are illustrative starting points, not an authorization recommendation
for your cluster.** Confirm every role and ACL path with your PVE
administrators and security review before adopting it, exactly as the
[README production runbook](../README.md#2-pre-create-groups-and-bind-their-roles)
advises for its own example binding.

## How to read these recommendations

A Vault role in this engine is thin. It stores only `group`, `user_prefix`,
`realm`, `ttl`, and `max_ttl` — it carries no privileges of its own. All
authorization lives in the ACL binding attached to the PVE group, which a
cluster administrator creates out-of-band. The engine's only involvement is
dropping each synthetic user into that group at issuance time.

So a recommendation here is really a **triple**:

```
Vault role name  →  PVE group  →  PVE role binding(s) at a path
```

The Vault role name also becomes part of the synthetic userid
(`{user_prefix}-{role}-{random}@{realm}`), so it shows up in PVE task logs and
audit output. Short, descriptive names read better there.

## Verify the built-in roles on your cluster first

The bindings below reference PVE built-in roles. Their exact privilege sets
have shifted across PVE major versions. Before adopting any of them, list what
your cluster actually defines and confirm the privileges match your intent:

```bash
pveum role list
```

## The starter set

| Vault role | PVE group | Binding | TTL / max TTL | Typical consumer |
|---|---|---|---|---|
| `auditor` | `vault-auditors` | `PVEAuditor` at `/` (propagating) | 1h / 24h | Monitoring, inventory sync, CMDB, `terraform plan` |
| `vm-operator` | `vault-vm-operators` | `PVEVMUser` at `/vms` | 1h / 8h | On-call runbooks: power cycle, console, backup |
| `vm-admin` | `vault-vm-admins` | `PVEVMAdmin` at `/pool/<team>` | 30m / 4h | `terraform apply`, Packer, CI provisioning |
| `backup-operator` | `vault-backup-operators` | `PVEVMUser` at `/vms` **and** `PVEDatastoreUser` at `/storage/<backup-store>` | 2h / 12h | Scheduled backup jobs |
| `template-builder` | `vault-template-builders` | `PVETemplateUser` at `/vms/<template-id>` **and** `PVEVMAdmin` at `/pool/<build>` | 30m / 2h | Golden-image pipelines |

Each role assumes the mount is already configured and the provisioner token is
in place (README sections 1, 3, and 4). Role writes validate group existence,
`Realm.AllocateUser` on the realm, and effective propagated `User.Modify` at
the per-group path, so a missing group or a `--propagate 0` grant fails at
`vault write` time rather than at issuance.

### `auditor`

Read-only access for systems that inspect the cluster but never change it.

```bash
pveum group add vault-auditors \
  --comment "Vault read-only lease group"

pveum acl modify / \
  --group vault-auditors \
  --role PVEAuditor \
  --propagate 1

vault write proxmox/roles/auditor \
  group="vault-auditors" \
  ttl=3600 \
  max_ttl=86400
```

A propagating grant at `/` is cluster-wide read, which includes VM
configuration, storage configuration, and cluster state. If that is broader
than your policy allows, bind at `/vms` or at a specific pool instead.

### `vm-operator`

Day-to-day operational access to running guests without the ability to create,
destroy, or reconfigure them.

```bash
pveum group add vault-vm-operators \
  --comment "Vault VM operator lease group"

pveum acl modify /vms \
  --group vault-vm-operators \
  --role PVEVMUser \
  --propagate 1

vault write proxmox/roles/vm-operator \
  group="vault-vm-operators" \
  ttl=3600 \
  max_ttl=28800
```

### `vm-admin`

Full guest administration, including create and destroy. Scope it to a pool
rather than `/vms` unless the consumer genuinely needs the whole cluster.

```bash
pveum group add vault-vm-admins \
  --comment "Vault VM admin lease group"

pveum acl modify /pool/platform \
  --group vault-vm-admins \
  --role PVEVMAdmin \
  --propagate 1

vault write proxmox/roles/vm-admin \
  group="vault-vm-admins" \
  ttl=1800 \
  max_ttl=14400
```

### `backup-operator`

Backup jobs need two distinct privileges: the ability to back up the guests,
and the ability to allocate space on the backup datastore. A single group can
carry both bindings — PVE resolves the union, and the engine still only adds
the synthetic user to that one group.

```bash
pveum group add vault-backup-operators \
  --comment "Vault backup operator lease group"

pveum acl modify /vms \
  --group vault-backup-operators \
  --role PVEVMUser \
  --propagate 1

pveum acl modify /storage/backup-nfs \
  --group vault-backup-operators \
  --role PVEDatastoreUser \
  --propagate 1

vault write proxmox/roles/backup-operator \
  group="vault-backup-operators" \
  ttl=7200 \
  max_ttl=43200
```

### `template-builder`

Image pipelines typically clone from a template they may only read, into a pool
they fully administer. Two bindings again, on one group.

```bash
pveum group add vault-template-builders \
  --comment "Vault template builder lease group"

pveum acl modify /vms/9000 \
  --group vault-template-builders \
  --role PVETemplateUser

pveum acl modify /pool/build \
  --group vault-template-builders \
  --role PVEVMAdmin \
  --propagate 1

vault write proxmox/roles/template-builder \
  group="vault-template-builders" \
  ttl=1800 \
  max_ttl=7200
```

## Per-team variants

For multi-tenant clusters, clone a role per team rather than widening one
role's scope. One Vault role should equal one blast radius, which is also why
the README recommends one PVE group per Vault role or use case.

```bash
pveum group add vault-vm-admins-payments \
  --comment "Vault VM admin lease group (payments)"

pveum acl modify /pool/payments \
  --group vault-vm-admins-payments \
  --role PVEVMAdmin \
  --propagate 1

vault write proxmox/roles/vm-admin-payments \
  group="vault-vm-admins-payments" \
  ttl=1800 \
  max_ttl=14400
```

Pair each Vault role with its own Vault policy so that a team can only reach
`proxmox/creds/vm-admin-payments`.

## TTL guidance

Bias short. Renewal costs one `PUT /access/users` against the cluster, and
`max_ttl` is captured in the lease at issue time, so a long ceiling is a
commitment you cannot shorten for credentials already outstanding.

- **Machine consumers that renew** (CI, IaC, image pipelines) — 30m TTL, 2–4h
  max. The job either finishes or renews.
- **Human or long-poll consumers** (on-call runbooks, monitoring agents) —
  1–2h TTL, 8–24h max.

Leaving `ttl`/`max_ttl` unset on the role falls back to `config.default_ttl` /
`config.default_max_ttl`, then to Vault's system defaults. `config.default_ttl`
is a fallback, not a cap. See the TTL section in
[ARCHITECTURE.md](ARCHITECTURE.md) for the full precedence rules.

## Userid length budget

The assembled userid must be ≤ 64 characters including the realm:

```
len(user_prefix) + 1 + len(role) + 1 + 8 + 1 + len(realm) <= 64
```

With the defaults `user_prefix=vault` and `realm=pve`, that leaves 45
characters for the role name. Every name in this document fits comfortably —
the longest, `vm-admin-payments`, uses 17 of the 45. A longer realm or prefix
narrows the budget; role writes reject an over-budget name up front rather
than failing at issuance.

## Operational notes

- **Changing a group's ACL bindings changes the effective access of every
  outstanding credential in that group, immediately.** Treat a `pveum acl
  modify` on a live group as a production change, not a role redefinition.
- **Deleting a Vault role does not revoke its outstanding leases.** Already
  issued credentials remain valid until they expire or are explicitly revoked;
  renew and revoke work from the lease's stored userid, not from the role.
- **The engine never creates groups or ACL bindings.** Every group in this
  document must exist, and be bound, before its Vault role is written.
