# Proxmox VE Secrets Engine

Vault secrets engine that issues **dynamic Proxmox VE API tokens**. Each
lease creates a dedicated, throwaway PVE user, adds it to a pre-configured
PVE group (which the operator has already bound to the desired ACL roles),
and mints an API token on it. Revocation deletes the user, which cascades
and removes its token(s), group memberships, and ACL entries in one call.

## Service API Summary
- Base URL: `https://<host>:8006/api2/json`
- Target version: Proxmox VE 9.2.10
- Authentication (engine → Proxmox): API Token header —
  `Authorization: PVEAPIToken=<user>@<realm>!<tokenid>=<secret>`
- Credential Types: Proxmox API tokens (`tokenid` + `secret`), one per
  lease, bound to a synthetic per-lease PVE user
- Lifecycle: full dynamic create/delete — Proxmox supports user and token
  creation/deletion natively, so no static-secret fallback is needed

## Configuration

```
POST <mount>/config
{
  "address": "https://pve.example.com:8006",
  "token_id": "vault-admin@pve!root-token",
  "token_secret": "<uuid-secret>",
  "tls_skip_verify": false,      # default false; prefer ca_cert for self-signed
  "ca_cert": "<PEM-encoded CA>", # optional CA bundle for self-signed certs
  "default_ttl": 3600,
  "default_max_ttl": 86400
}
```

**Validation**: The write operation rejects the request with a clear error if
`default_ttl` > `default_max_ttl` (when both are set). This is an input-sanity
guard so operators don't silently get a value different from what they
specified (the TTL precedence math at issuance would otherwise cap it without
complaint).

`token_id`/`token_secret` should use a **least-privilege custom role**
with only the permissions the engine requires: `User.Modify` (create,
delete, and manage group membership of synthetic users),
`Realm.AllocateUser` (allocate users in the target realm), and
`Sys.Audit` (read group metadata for validation). These privileges allow
the engine to create users and add them to **operator-pre-created PVE
groups**, which the operator (typically a cluster admin using
`root@pam`) has separately bound to the desired ACL roles.

**Required privilege scoping** (confirmed on PVE 9.2.10):
- `User.Modify` on `/access/groups` (PARENT PATH) — required for user creation, renewal (PUT expire), and revocation
- `Realm.AllocateUser` on `/access/realm/<realm>` (per realm) — required for user creation
- `Sys.Audit` on `/access/groups` — required for group-existence validation at role-write time (via `GET /access/groups/{group}`). **Trade-off**: This privilege is required ONLY to enable early failure (validating group existence at role-write time). An alternative is to drop the precheck and let credential issuance fail if the group is missing, which removes `Sys.Audit` from the required set. The precheck + `Sys.Audit` approach is recommended for better operator ergonomics.

**Literal ACL grant commands**:
```bash
# Create a custom VaultProvisioner role with User.Modify, Realm.AllocateUser, Sys.Audit
pveum acl modify /access/groups --user vault-admin@pve --role VaultProvisioner --propagate 1
pveum acl modify /access/realm/pve --user vault-admin@pve --role VaultProvisioner
```

**IMPORTANT**: The `/access/groups` grant MUST be propagating (`--propagate 1`, which is PVE's default). The parent-path grant at `/access/groups` satisfies the renewal/revocation privilege check (which PVE checks at the parent) AND satisfies the creation per-group check at `/access/groups/<group>` ONLY via propagation. An operator who sets `--propagate 0` gets a broken partial config: user creation will 403 (per-group check unsatisfied) while renew/revoke still work — a confusing partial failure. Always use propagating grants for `/access/groups`.

**Per-operation privilege-path asymmetry** (discovered in live testing):
- User creation (`POST /access/users` with `groups=<group>`) checks `User.Modify` at the PER-GROUP path `/access/groups/<group>` AND `Realm.AllocateUser` at `/access/realm/<realm>`. A token scoped ONLY to `/access/groups/<group>` + `/access/realm/<realm>` (with NO grant at `/access` or `/access/groups` parent) successfully creates users already in the group.
- User renewal (`PUT /access/users/{userid}` with `expire` only) checks `User.Modify` at the PARENT `/access/groups` (NOT per-group). A token scoped only to `/access/groups/<group>` returns 403 on renewal.
- User revocation (`DELETE /access/users/{userid}`) also checks `User.Modify` at the PARENT `/access/groups`.

Because PVE's user-update and user-delete endpoints check the PARENT path (`/access/groups`), per-group scoping is NOT achievable for renewal and revocation. The admin token must hold `User.Modify` at `/access/groups` (parent), which propagates to all child group paths.

**Threat model** (see Security Considerations section for full detail): `User.Modify` at `/access/groups` grants **cluster-wide user administration**, creating a self-escalation primitive in the compromise case.

This design deliberately uses **group membership** instead of direct
per-lease ACL grants. Proxmox enforces anti-privilege-escalation on
`PUT /access/acl`: a principal cannot grant roles it does not itself
hold at the target path (confirmed on PVE 9.2.10: attempting to grant
PVEVMAdmin at `/vms/200` with a token lacking that role returns
`403: Permission check failed (/vms/200,
Permissions.Modify|VM.Allocate)`). By using group membership, the
engine's admin token **never needs to hold the roles it effectively
confers in the non-compromise case** — those are bound
to groups once by a cluster admin. Group-membership writes are
authorized solely by `User.Modify` (the group-to-role bindings are
out-of-band and outside the engine's privileges). However, the required `User.Modify` at `/access/groups` is cluster-wide user administration; see the Security Considerations section for the full threat model analysis.

A **full-admin** token (`root@pam` or `PVEAdmin`-equivalent at `/`) can
bypass the anti-escalation check (full-admins hold all roles). See the Security Considerations section for a comparison of the scoped-user-admin model versus full-admin.

On config write, the plugin validates the admin token's connectivity and
privileges with two checks: `GET /version` (lightweight reachability/TLS
handshake test), and **`GET /access/permissions`** (privilege-bearing
call that returns the effective permissions of the token as a **tree
structure**, which the plugin parses to confirm it holds `User.Modify`
at `/access/groups` and `Sys.Audit` on `/access/groups` — the
`Realm.AllocateUser` privilege is realm-specific and validated at
role-write time, see Roles section). A 403 on the permissions call
should be surfaced clearly (indicates the token lacks required
privileges). Per-role group existence and realm privileges are validated
separately at role-write time (via `GET /access/groups/{group}` and
parsing permissions for `Realm.AllocateUser` at
`/access/realm/<role.realm>`).

**Implementation note (permission-tree ancestor walk)**: `GET /access/permissions`
returns effective privileges keyed by the ACL paths that have explicit
entries. A grant made higher up with `propagate=1` will NOT appear as a
literal key for deeper paths. Therefore, privilege checks must test the
exact path AND every ANCESTOR path (walking up `/access/groups` →
`/access` → `/`), treating a propagated privilege on an ancestor as
satisfying the requirement.

**Confirmed PVE 9.2.10 (PVE_PROBES.md Probes 1, 1b):** the inner value IS the propagate flag (0/1), and `?path=`/`?userid=` resolve effective privileges server-side. Config-time validation reads the admin token's OWN permissions (bare `GET /access/permissions`) — no extra grant needed. The client-side ancestor walk (`HasPrivilege`) remains the chosen approach; a server-side `?path=` query is a viable simplification ("Lazy Way", Probe 1b) but is optional.

```
GET <mount>/config
```
Returns `address`, `tls_skip_verify`, `ca_cert`, `default_ttl`,
`default_max_ttl`, and `token_id`. The `token_secret` is never read back for
security. `token_id` (e.g., `vault-admin@pve!root-token`) is an identity, not
a credential — knowing it grants nothing, and returning it enables operators
to verify which PVE token the mount currently uses.

```
DELETE <mount>/config
```
Clears the stored admin credentials and connection configuration.
**Behavior with outstanding leases**: Because revocation requires the
admin token, deleting config while leases are outstanding strands them
(their PVE users/tokens cannot be revoked by the engine). The
implementation MUST require an explicit `force=true` parameter. Without
`force=true`, the DELETE is refused with a clear error. **Rationale**:
The engine does not (and cannot reliably) track outstanding leases — a
Vault secrets-engine backend has no reliable lease-count API, and a
counter would drift on crashes. Therefore the engine cannot conditionally
refuse based on lease existence. Requiring `force=true` is an explicit
acknowledgement by the operator. **WARNING**: Deleting the config removes
the admin credentials, so any OUTSTANDING leases become NON-REVOCABLE and
NON-RENEWABLE by the engine — renewal also loads config to reach PVE, so
it fails immediately too. Their PVE users/tokens will remain until they hit
their `expire` backstop or are cleaned up out-of-band. Operators should
revoke outstanding leases BEFORE deleting config.


## Roles

```
POST <mount>/roles/:name
{
  "ttl": 3600,
  "max_ttl": 86400,
  "group": "vault-vm-admins",           # Pre-existing PVE group name
  "user_prefix": "vault",                # synthetic userid prefix
  "realm": "pve"                         # target realm (default: pve)
}
```

**Validation**: The write operation rejects the request with a clear error if
`ttl` > `max_ttl` (when both are set). This is an input-sanity guard so
operators don't silently get a value different from what they specified (the
TTL precedence math at issuance would otherwise cap it without complaint).

`group` is validated against `GET /access/groups/{group}` at write time.
A nonexistent group returns HTTP 500 + body `"does not exist"` (NOT 404, Probe 5); the precheck keys on that body.
The group must already exist on the Proxmox cluster and have been
pre-bound by an operator (typically via `root@pam` or a cluster admin) to
the desired PVE role(s) at the desired ACL path(s). The engine does NOT
create groups — operators create and bind them once, out-of-band, before
defining the corresponding Vault role.

**Role-write validation** also parses `GET /access/permissions` to
confirm the admin token holds `Realm.AllocateUser` at
`/access/realm/<role.realm>` (since `realm` is a per-role field unknown
at config time), using the same ancestor-path walk validation described above under Configuration validation.

Role-write additionally verifies `User.Modify` is effective at the exact **per-group path** `/access/groups/<role.group>`. PVE's permissions tree exposes the propagate flag (`:0` vs `:1`, Probe 9), and user creation checks the per-group path — so a `--propagate 0` grant at `/access/groups` passes the parent check but fails creation. Checking the per-group path at role-write time catches this misconfiguration early.

If the operator renames, deletes, or re-binds the group after the role
is created, issuance for that role will fail (group not found) or
silently change the effective privileges conferred (if the group's ACL
binding was altered). **Because Proxmox evaluates ACLs at request time,
re-binding a group changes the effective privileges of EVERY
OUTSTANDING credential immediately, not just future issuance.** 
Additionally, two distinct operator actions have different blast-radius profiles:

- **(a) Operator removes the admin token's grant on `/access/groups`**: both
  `DELETE /access/users/{userid}` and `PUT /access/users/{userid}` (renewal)
  check `User.Modify` at the parent `/access/groups` path. Removing that grant
  means outstanding leases become **NON-REVOCABLE and NON-RENEWABLE** and their
  PVE users/tokens orphan on the cluster.

- **(b) Operator deletes the PVE group**: revocation **still succeeds** — the
  `DELETE /access/users/{userid}` call checks `User.Modify` at the parent path
  `/access/groups`, which remains intact after a group deletion; nothing orphans.
  Only **renewal fails**, and it fails at the engine's read-back assertion (PVE
  silently drops the now-missing group on the `PUT` modify with HTTP 200, so the
  subsequent `GET` reveals group membership is gone), not at a permission check.

These are out-of-contract operator actions.

**Guidance**: enforce a **1:1 mapping** between a Vault role and a PVE
group to avoid shared blast radius. If two Vault roles share the same PVE
group, all credentials issued from either role receive identical effective
privileges (the group's ACL binding). Separate use cases should have
separate groups.

`user_prefix` and the role name (`:name`) are validated against the
Proxmox userid character set at config/role-write time. From the PVE API
schema, the userid regex is:
```
^([^\s:/]+)@([A-Za-z][A-Za-z0-9.\-_]+)(?:!([A-Za-z][A-Za-z0-9.\-_]+))?$
```
The username part (before `@`) may contain any characters EXCEPT
whitespace, `:`, and `/`. The realm and tokenid must start with a letter
then `[A-Za-z0-9._-]`.

The synthetic userid format is `{user_prefix}-{role}-{random}@{realm}`,
where `{random}` is an 8-character base32 suffix (~40 bits entropy,
collision probability negligible at typical issuance rates; implementation
may tune). **Confirmed on PVE 9.2.10**: the full userid (including
`@<realm>`) must be ≤ 64 characters. `POST /access/users` returns HTTP 400
with format error "user name '<name>@<realm>' is too long (N > 64)"
otherwise. The length budget is:
```
len(user_prefix) + 1 + len(role) + 1 + len(random_suffix) + 1 + len(realm) ≤ 64
```
(the three `1`s are the `-`, `-`, and `@` separators). With an 8-character
random suffix and realm `pve` (3 chars), fixed overhead = 8 + 3 (two `-`
and one `@`) + 3 (realm) = 14, leaving 50 characters to share between
`user_prefix` and `role`. The exact budget scales with realm length (a
longer realm leaves fewer chars). Reject `user_prefix` or role name values
that: (a) are empty, or contain whitespace, `:`, `/`, `@`, or `!` (the `@` and `!` break
the `<user>@<realm>!<tokenid>` userid/token-header grammar), or (b) would cause the
assembled userid to exceed the 64-character limit. Invalid values are
rejected at config/role-write time with a clear error rather than failing
at credential-issuance time.


`realm` specifies the authentication realm for synthetic users (default:
`pve`). The built-in `pve` realm (Proxmox VE native auth) is the
sensible default — it's local and requires no external identity provider
dependency. Operators may target another realm if their setup requires
it, but must ensure the realm exists and is accessible. The synthetic
userid format remains `{user_prefix}-{role}-{random}@{realm}`.

```
GET <mount>/roles/:name
LIST <mount>/roles
DELETE <mount>/roles/:name
```

Deleting a role does **not** revoke its outstanding leases — already-issued
credentials remain valid until their lease expires or is explicitly revoked.
Renew and revoke operations rely on `pve_userid` stored in the lease's
internal data, not on the role still existing.

## Credentials

```
GET <mount>/creds/:role
```

This endpoint is implemented as a Vault **ReadOperation that mutates
state** — it provisions a new Proxmox user + token on each call. This is
the standard Vault dynamic-secrets convention despite violating HTTP GET
idempotency expectations. The credential (token secret) is returned
**only once** at issue time and is non-reproducible, consistent with
Proxmox's own "token shown once" behavior and Vault dynamic secrets
semantics.

Response:
```json
{
  "lease_id": "<mount>/creds/myrole/2n1f...",
  "lease_duration": 3600,
  "renewable": true,
  "data": {
    "pve_userid": "vault-myrole-a1b2c3@pve",
    "token_id": "vault-myrole-a1b2c3@pve!vault",
    "token_secret": "1b3f5e2a-....-uuid"
  }
}
```

The `pve_userid` and `token_id` use the realm configured in the role
(default `@pve`).

## Implementation Notes

### Service API Calls

**Create** (issue on `creds/:role` read), in order:
1. `POST /access/users` — `userid=<user_prefix>-<role>-<random>@<realm>`,
   `enable=1`, no `password` (token-only auth, no interactive login
   needed), `groups=<role.group>` (add the synthetic user to the
   operator-pre-created PVE group at creation time), and
   `expire=<lease_expiry_unix>` as a Proxmox-side backstop
2. `POST /access/users/{userid}/token/{tokenid}` — fixed `tokenid`
   (e.g. `vault`), **`privsep=0`**, no token-level `expire` (the user-level
   `expire` set in step 1 is the sole Proxmox-side backstop — confirmed on
   PVE 9.2.10: a token whose owning user has an expired `expire` is
   rejected at authentication with 401) — response `value` is the
   one-time-shown secret returned as `token_secret`

Order matters: user must exist before token creation. The PVE API
accepts `groups` at user creation time, so the synthetic user is created
already in the group (no separate group-membership step needed). `groups` is
a `pve-groupid-list`: send it as ONE comma-separated field (never array-repeated).
**Confirmed PVE 9.2.10 (PVE_PROBES.md GROUPADD): single-call create with `groups=<group>` lands membership**,
verifiable via `GET /access/users/{id}.groups` OR `GET /access/groups/{id}.members`. Because
PVE returns HTTP 200 even when it silently drops an unresolvable group id (observed on
modify/append; on create, PVE instead REJECTS with HTTP 500 `"no such group"` — the
read-back assertion covers both paths), the engine MUST
read the user back after create and assert the group is present before minting the token. The
plugin **MUST** explicitly set `privsep=0` on token creation. Proxmox
defaults to `privsep=1` (privilege separation enabled), which requires the
token principal to have its own separate ACL; omitting `privsep` or using
`privsep=1` yields a token with **zero effective permissions** (the
token's ACL would be empty). With `privsep=0`, the token inherits the
synthetic user's effective ACL (conferred via the group membership in step
1), matching this design's group-membership pattern. The synthetic
per-lease user is itself the disposable security boundary (unique per
lease, cascade-deleted on revoke), so privilege separation adds no benefit
and would only require a second ACL call on the token principal, adding
another failure/compensation point.

The `<realm>` in the userid is taken from the role's `realm` field
(default `pve`).

**Issuance ordering detail** (see WAL-Based Orphan Recovery section for the full mechanism): ALL provisioning work, including WAL write/delete, occurs BEFORE the engine returns the Secret to the caller. The Vault SDK does not provide a post-lease-write hook — Vault core registers the lease AFTER the backend returns the *logical.Response. Therefore the complete issuance sequence (including WAL cleanup) must finish before returning the Secret.

**Update**: not supported — dynamic secrets have no update path. Role
changes only affect leases issued after the change.

**Delete** (on lease revoke): `DELETE /access/users/{userid}` — single
call, cascades to delete the user's token(s), group memberships, and
associated ACL entries. Store `pve_userid` in the lease's internal data
so revoke doesn't need to re-derive it.

### Lease Renewal

Vault-side lease renewal extends the lease TTL up to the effective
`max_ttl` captured at issuance time (see TTL Precedence below). Renewal
also issues `PUT /access/users/{userid}` re-sending `expire`+`groups`+`enable`+`append=1` together. Note that `enable=1` re-enables a user an operator disabled out-of-band, so disabling the PVE user is NOT a sticky kill-switch across renewal — to terminate a lease, revoke it in Vault (which deletes the user). **Revocation is the only supported kill path; out-of-band PVE user disable is not sticky across renewal.**
**Confirmed on PVE 9.2.10 (PVE_PROBES.md Probe 7): `PUT /access/users` is FULL-REPLACE.**
An expire-only PUT WIPES the `groups` array (observed `groups:[]`), stripping the credential's
effective privileges. Renewal therefore MUST re-send the target group. The full-replace wipe
is confirmed; the preserve path (re-sending `groups` retains membership) is confirmed by
Probe RENEWAL-PRESERVE (17 Aug 2026 — groups `["vault-test-grp"]` read back, expire advanced
1786986804→1786990429). The runtime read-back assertion remains as defense-in-depth. The group is
read from the lease's InternalData (`group` field), NOT from the role — the role may have
been deleted or re-bound since issuance. After the PUT, the engine reads the user back
(`GET /access/users/{userid}`) and asserts the group is still present (PVE silently drops
unresolvable group ids with HTTP 200 on modify/append; on create, PVE instead REJECTS with
HTTP 500 `"no such group"` — the read-back assertion covers both paths — PVE_PROBES.md GROUPADD). If a renewal
request would exceed `max_ttl`, the new TTL is capped at `max_ttl`.

If the `PUT /access/users/{userid}` call returns the body `"no such user"` (the synthetic user
was removed out of band), the renewal FAILS — the lease then runs out its
current TTL and normal revocation cleans up (a `"no such user"` body on the eventual revoke
DELETE is already treated as success).

### TTL Precedence

At credential issuance, the effective TTL and max_ttl are computed using
role values with config defaults as fallbacks:

```
role_ttl     = role.ttl     or config.default_ttl
role_max_ttl = role.max_ttl or config.default_max_ttl
eff_max_ttl  = min(role_max_ttl, Vault mount/system max TTL)
eff_ttl      = min(role_ttl, eff_max_ttl)          # no requested TTL at issuance
```

Key points:
- `config.default_ttl` and `config.default_max_ttl` are **fallback values**
  used only when the role does not define its own `ttl` or `max_ttl`.
- **There is no issuance-time requested TTL**: `<mount>/creds/:role` declares no `ttl` field
  (matching the database and terraform secrets engines). A requested `increment` applies only
  on lease renewal (`req.Secret.Increment`), capped at `eff_max_ttl` measured from the
  original issue time.
- Vault's mount/system maximum TTL remains the absolute hard ceiling above
  all other limits.
- **Unlimited TTL is refused at issuance**: if `eff_ttl` resolves to 0 (all sources unset),
  issuance fails with a clear error rather than creating a never-expiring PVE user. The
  `expire` backstop (see Additional Security Considerations) is defense-in-depth against
  delayed/failed Vault revocation and must not be disabled; an `expire=0` user would have no
  backstop. Operators must set a finite ttl/max_ttl on the role or a config default.
- The computed `eff_max_ttl` is captured in the lease's internal data at
  issue time and governs all subsequent renewals for that lease.
- On renewal, the lease TTL is extended up to this effective `max_ttl`, and
  the Proxmox-side `expire` backstop is updated to match the new expiry
  via the full-replace `PUT /access/users` that also re-sends `groups`+`enable`+`append=1` (see Lease Renewal).

### Revocation

Single `DELETE /access/users/{userid}` call, as above. The engine should
treat a **DELETE for a nonexistent user as success** (idempotent).
**Confirmed PVE 9.2.10 (PVE_PROBES.md Probe 3): PVE returns HTTP 500 with body `"no such user (...)"`, NOT 404.**
Idempotency therefore keys on the BODY STRING (`"no such user"`), never on a 404 status.

If the delete call fails for other reasons (network blip, transient
error), Vault's built-in revocation retry/backoff handles retry.

### Storage Schema

The plugin persists three categories of data in Vault's encrypted storage
barrier:

**Config storage** (single entry at `config`):
- `address`, `tls_skip_verify`, `ca_cert`, `default_ttl`, `default_max_ttl`
- `token_id`, `token_secret` — both are stored encrypted; `token_id` is
  returned on GET (identity, not a credential), `token_secret` is never read
  back via the API

**Role storage** (one entry per role under `roles/<name>`):
- `group`, `user_prefix`, `ttl`, `max_ttl`, `realm`

**Lease internalData** (persisted on each issued credential's Secret,
used at renew/revoke time):
- `pve_userid` — the synthetic Proxmox user ID created for this lease
  (fixed at issue time)
- `group` — the target PVE group the synthetic user was added to (fixed at issue time). Re-sent on every renewal PUT (PVE PUT is full-replace) so renewal does not depend on the role still existing.
- `expire` — the Unix epoch timestamp set on the Proxmox-side user
  (mutable: rewritten on each successful renewal to match the new lease
  expiry)
- `role_name` — the role this credential was issued from (fixed at issue
  time)
- `effective_max_ttl` — the computed maximum TTL captured at issue time
  (fixed: governs renewals for the life of the lease)

### Proxmox Cluster Considerations

`POST` and `DELETE` operations on `/access/users` are **cluster-wide
configuration writes** that require quorum and take a cluster-wide lock.

**Failure modes**:
- **Quorum loss**: User creation/deletion will fail cluster-wide until
  quorum is restored. Surface these failures as retryable errors (Vault's
  built-in retry/backoff handles transient unavailability).
- **Lock contention**: High issuance or revocation churn may hit lock
  contention, causing transient failures. These should also be surfaced as
  retryable errors with exponential backoff.

The current configuration accepts a single `address` (one Proxmox node
endpoint). A future enhancement could support multiple endpoints for read
failover, but write operations (user/ACL management) would still target the
cluster configuration layer and are subject to the same quorum and locking
requirements regardless of which node endpoint is used.

### HTTP Client and Connection Pooling

The engine uses a **single, reused HTTP client** configured with the stored
TLS settings (`tls_skip_verify` and/or `ca_cert`) at config-write time.
This client is pooled and shared across all requests to the Proxmox API,
rather than creating a new client per request. The client is reconfigured
when the `<mount>/config` is updated.

### Root Rotation

`POST <mount>/rotate-root` — out of scope for v1. Rotating a full-admin
token is high-blast-radius and there's no atomic "rotate and verify"
primitive in the Proxmox API for the token currently in use; document as
a manual operation (create new token, update `<mount>/config`, delete old
token) rather than an automated endpoint. Operators can read the current
`token_id` via `GET <mount>/config` to identify the token being replaced
and confirm the swap.

### Error Handling

- `595`/`5xx` from Proxmox on user/token create → surface as Vault
  internal error, no partial state left (if the token-creation step
  fails after user creation, best-effort delete the user before
  returning the error, so a failed issuance doesn't leak an orphaned
      identity — then delete the WAL entry by the id returned from PutWAL
      ONLY if the compensating DeleteUser returned nil or ErrNotFound;
      if DeleteUser fails transiently, LEAVE the WAL entry for walRollback
      to retry — never orphan a user with no surviving WAL entry)
- **Userid collision** (random suffix conflict on `POST /access/users`
  → **PVE returns HTTP 500 with body `"...already exists"`, NOT 409**
  (confirmed PVE 9.2.10, Probe 2); the engine detects collision by BODY STRING.)
  → For each suffix attempt: call `framework.PutWAL(ctx, storage, kind, walUser{UserID: userid})`
  which RETURNS a WAL id string → attempt `POST /access/users` → on ErrConflict (body
  "already exists"), call `framework.DeleteWAL(ctx, storage, walID)` with THAT id (NOT the
  userid — the SDK keys WALs by the returned id), generate a new random suffix, and loop
  (bounded retry count). On success, proceed to token creation (step 3 in the issuance
  ordering), then continue through step 5 (return the Secret). Each attempt keeps its own
  walID. This per-attempt WAL ordering prevents orphaning the userid from the WAL entry when
  retrying with a new suffix.
- **Token creation conflict** — **PVE returns HTTP 400 with body `"Token already exists"`, NOT 409**
  (confirmed PVE 9.2.10, Probe 6b). Detected by body string. — Since each lease uses a
  unique freshly-created userid (step 2), and token ids are scoped per-user, a token-creation
  conflict at this step is **not expected** to occur. If it does, treat it like any other
  `CreateToken` error: best-effort `DeleteUser`, then `DeleteWAL` ONLY if `DeleteUser`
  returned `nil` or `ErrNotFound`; if `DeleteUser` fails transiently, LEAVE the WAL entry
  for walRollback to retry. Surface as internal error.
- `403` on config validation → surface clearly; required privileges
  should be checked at `POST <mount>/config` time via the
  privilege-bearing call (`GET /access/permissions` parsed as a tree for
  the specific `User.Modify` and `Sys.Audit` on `/access/groups`, with
  ancestor-path walk as described in the Configuration section); the
  realm-specific `Realm.AllocateUser` at `/access/realm/<realm>` is
  validated per-role at role-write time

### WAL-Based Orphan Recovery

To handle process death or Vault failover mid-provisioning, the engine uses
Vault's Write-Ahead Log (WAL) pattern:

**Issuance ordering** (ALL steps occur BEFORE returning the Secret to the caller):
1. `framework.PutWAL(ctx, storage, kind, walUser{UserID: userid})` — RETURNS a WAL id
   string — written for EACH userid creation attempt (including retries on ErrConflict
   suffix collision). Keep the returned id for the matching DeleteWAL.
2. `POST /access/users` — create the synthetic PVE user (with
   `groups=<role.group>`, `expire=<lease_expiry_unix>`)
3. `POST /access/users/{userid}/token/{tokenid}` — mint the API token
   (`privsep=0`)
4. `framework.DeleteWAL(ctx, storage, walID)` using the id returned by PutWAL (NOT the
   userid) — if this step FAILS, the handler MUST NOT return the Secret; instead it MUST
   best-effort `DELETE /access/users/{userid}` (cleanup the just-created user), then return
   an error to the caller. The caller retries and receives a fresh credential. Because no
   Secret/lease was returned, no live credential is exposed to a later WALRollback.
5. Return the `*logical.Response` with the Secret (Vault core then
   registers the lease)

**On ErrConflict collision retry**: call `framework.DeleteWAL(ctx, storage, walID)` for the
abandoned attempt's id, generate a new random suffix, and `PutWAL` again for the new userid
(capturing a NEW walID) before retrying at step 2. This per-attempt WAL ordering prevents
orphaning the userid from the WAL entry when retrying with a new suffix.

**Implement `WALRollback`** to handle orphaned WAL entries (those left
behind if Vault crashes or fails over between user creation and lease
registration):

1. For each WAL entry (representing a userid from a failed/incomplete
   issuance), issue `DELETE /access/users/{userid}`.
2. Treat a **nonexistent-user DELETE as success** (idempotent). PVE returns HTTP 500 + body `"no such user"` (NOT 404, Probe 3); the rollback keys on that body string.

**Division of responsibility**:
- **WALRollback**: Sweeps users left orphaned by a crash BETWEEN `PutWAL`
  (step 1) and `DeleteWAL` (step 4) — i.e., a WAL entry exists but
  issuance never completed / the Secret was never returned to the caller,
  so no lease was registered by Vault core. WALRollback runs on Vault
  startup/unseal and periodically thereafter.
- **Vault's revocation retry**: Handles failed revocations. If a
  `DELETE /access/users` call fails for reasons other than ErrNotFound (body "no such user") (network
  blip, transient error), Vault's built-in revocation retry/backoff
  re-runs the Revoke operation until it succeeds (ErrNotFound treated as success).
  This is NOT WALRollback — it is Vault core retrying a failed revoke on
  an existing lease.
- **PVE `expire` backstop**: Caps any leaked user that slips through both
  mechanisms — the PVE user self-expires at the `expire` timestamp set at
  creation time, cutting off authentication even if the user is never
  deleted.

This ensures that users created but not fully leased are eventually swept,
preventing orphaned Proxmox identities from accumulating.

**Implementation note**: Vault's WAL minimum-age threshold (rollback skips
entries younger than the configured age) is a first-line guard against
racing with an in-flight issuance. A successfully-returned credential (step 5
completes) has no surviving WAL entry because step 5 is only reached after
step 4 (`framework.DeleteWAL`) succeeds. If step 4 fails, issuance errors
out and the just-created user is cleaned up (best-effort delete), so
WALRollback never faces a live returned credential.

**Accepted risk**: one narrow window is NOT covered — a crash between the
successful `DeleteWAL` (step 4) and Vault core persisting the returned
Secret/lease (after step 5 returns). In that window the WAL entry is already
gone and no lease exists, so neither WALRollback nor Vault revocation fires.
The PVE `expire` backstop only **neutralizes** the credential — authentication
is rejected once past `expire` (Probe 8) — it is **not** cleanup: the stale
user record persists in user.cfg until out-of-band removal. See the WAL
Rollback section of `docs/IMPLEMENTATION_PLAN.md` for full detail.

## Testing Strategy

### Unit Tests
- **Mocked Proxmox API client** — test all path handlers (config, roles,
  creds) in isolation
- **Path handler logic** — validate read/write/delete flows, input
  validation, TTL computation, error mapping
- **Role-write validation** — verify group existence check via
  `GET /access/groups/{group}`; verify create-flow adds user to group
- **TTL calculation** — verify precedence rules (see TTL Precedence
  section) are applied correctly at issuance and renewal
- **Error handling** — test compensation paths (orphaned user cleanup on
  mid-provisioning failure), idempotent deletion (ErrNotFound body "no such user" treated as success)
- **Userid sanitization** — verify `user_prefix` and role name validation
  against Proxmox userid character set and length limits

### Acceptance Tests
- **Environment gating** — tests prefixed `TestAcc*` run only when
  `VAULT_ACC=1` is set (HashiCorp convention)
- **Test environment** — run against a containerized or dev Proxmox VE
  instance with a test admin token
- **Full lifecycle coverage** — pre-create a PVE group bound to a test
  role; create credential → use the issued token to verify it can perform
  its scoped actions and **cannot** exceed them. **The primary privilege oracle is BEHAVIORAL**: call a group-role-gated endpoint with the issued token (e.g. `GET /cluster/resources?type=vm`, expect 200) — this is the only confounder-free proof (Probe GROUPADD / 6-fix-E). The `GET /access/permissions?userid=<userid>&path=/` server-side dump is OPTIONAL and requires a TEMPORARY cluster-wide `Sys.Audit` grant on the admin token; under the least-privilege admin it returns `403 (/access, Sys.Audit)` (Probe 6-fix-C/D, Probe CLEAN 5-B). If used, tear the grant down with the BARE `--delete` flag (`pveum acl modify / --user X --role Y --delete`, NOT `--delete 1`). The token's BARE `/access/permissions` reflects only the authenticating principal and is NOT evidence of the synthetic user's group-derived privileges (Probe 6). → renew the lease → revoke and confirm the user/token are deleted by asserting the `"no such user"` body (HTTP 500), not a 404.
- **Authorization contract canary** — assert the confirmed PVE 9.2.10
  behavior the design depends on: (a) direct `PUT /access/acl` of an
  unheld role by the admin token returns 403; (b) group-membership add
  succeeds and confers the group's role(s); (c) a token whose owning
  USER has an `expire` in the past is rejected at authentication (401);
  (d) after a renewal (`PUT /access/users/{userid}` re-sending `expire`+`groups`+`enable`+`append=1`),
  the issued token still holds the group's roles (read-back confirms `groups` preserved).
  PVE PUT is full-replace (Probe 7): an expire-only PUT WIPES groups; the canary guards
  against a regression to expire-only renewal. Add a control: expire-only PUT on a throwaway
  user leaves `groups:[]`. These four assertions guard against
  a future PVE version silently changing the authorization or expiry
  enforcement model the engine relies on. The user-level `expire`
  backstop behavior and the full-replace wipe behavior are confirmed on PVE 9.2.10;
  canary (d) serves as a regression guard in the acceptance suite (the decisive live evidence
  for the preserve path is Probe RENEWAL-PRESERVE, 17 Aug 2026 — groups `["vault-test-grp"]`
  read back, expire advanced 1786986804→1786990429). The control sub-assertion (expire-only PUT
  leaves `groups:[]`) guards against a future regression to expire-only renewal.
- **Failure injection** — simulate mid-provisioning failures (network
  error after user creation but before/during token creation) and
  verify best-effort cleanup; inject a `framework.DeleteWAL` failure at
  step 4 and assert (a) issuance returns an error (no Secret), and (b) the
  just-created PVE user is cleaned up (best-effort delete ran); test
  idempotent revocation (PVE body `"no such user"` (HTTP 500) treated as success); test root token
  lacking required privileges
- **Concurrent issuance** — test concurrent credential issuance to verify
  suffix-collision retry handling works correctly under load
- **WAL rollback** — simulate process death mid-provision (e.g., after user
  creation but before lease write) and verify WAL rollback sweeps the
  orphaned user
- **DELETE config guard** — assert that `DELETE <mount>/config` without
  `force=true` is refused with a clear error, and that DELETE with
  `force=true` succeeds (matching the documented MUST in the DELETE config
  behavior section)
- **Cluster failure modes** — test behavior under Proxmox quorum loss and
  ACL lock contention (should surface as retryable errors)
- **CI integration** — acceptance tests require live Proxmox credentials,
  so they run in a gated CI job (e.g., manual trigger or nightly), not on
  every PR

## Security Considerations

### Threat Model: Admin Token Compromise

**Admin token privileges and blast radius**: The engine's admin token requires `User.Modify` at `/access/groups` (with `--propagate 1`), `Realm.AllocateUser` at `/access/realm/<realm>`, and `Sys.Audit` at `/access/groups` (see Configuration section for full details on required privilege scoping, privilege-path asymmetry, and the ancestor-path walk validation). The required `User.Modify` at `/access/groups` grants **cluster-wide user administration** — the admin token can modify, expire, disable, or delete **any user** on the cluster, not just the engine's own synthetic users. There is no per-user scoping in PVE's authorization model.

**In the compromise case**, this creates a self-escalation primitive via TWO routes:

1. **Admin-user self-modification** (noisy): A compromised engine token can `PUT /access/users/<its own admin user>` with `groups=<any privileged group>` (e.g., a group bound to PVEAdmin at `/`) in a single call, then use its existing `privsep=0` token with those roles — effectively escalating to any role bound to any group. This modifies an existing admin user, which may be more visible in audit logs.

2. **New-user creation in privileged group** (quieter): A compromised engine token can simply `POST /access/users` to create a BRAND-NEW user directly in a privileged group (a group bound to an admin-level role) and mint a token on it — this is the engine's NORMAL issuance flow pointed at the wrong group. It requires only the privileges the engine uses every day (`User.Modify` at the per-group path via propagation from `/access/groups`, plus `Realm.AllocateUser`), modifies no existing admin user, and therefore looks like routine engine activity in PVE's audit log. This route is simpler, quieter, and harder to distinguish from legitimate issuance.

Both routes reach the same privilege ceiling (any role bound to any group under `/access/groups`), but the new-user route is operationally quieter. The "never needs to hold the roles it confers" framing is accurate only in the NON-COMPROMISE case; a compromised token can grant itself any role bound to any group under `/access/groups`.

**Honest comparison to full-admin**: The engine token scoped to user/group administration (as described above) **cannot directly edit ACLs** (`Permissions.Modify` is not granted) and **cannot directly touch VMs, storage, or nodes** — but it IS cluster-wide user administration, one API call away from any role bound to any group. This is NOT "least privilege" in the compromise case; it is "scoped to user/group administration" with the blast radius bounded by what roles operators bind to groups. A full-admin token (`root@pam` or `PVEAdmin`-equivalent at `/`) additionally holds direct ACL and resource management permissions, a broader initial surface. The scoped-user-admin model avoids granting `Permissions.Modify` and direct resource roles, narrowing the blast radius in the non-compromise case. The group model is preferred over full-admin when operators can pre-create groups and want to avoid granting direct ACL/resource management permissions, but it does not achieve true least-privilege in the compromise case.

**Partial containment recommendation**: Operators should keep `/access/groups` free of any group bound to admin-level roles at `/` (or other broad paths). The reachable privilege ceiling for a compromised engine token is bounded by exactly what operators bind to groups under `/access/groups`. This does not prevent the compromise, but limits the escalation target to the specific roles operators have explicitly bound to engine-managed groups, rather than cluster-wide admin. Naming the quieter escalation path (new user in privileged group) makes this containment recommendation land harder: the ONLY real bound on the compromise case is what operators bind to reachable groups, since the engine can freely place users into any of them using its normal workflow.

**Mitigation**: The admin token secret is the highest-value secret in the system; restrict the Vault policy on `<mount>/config` write/read to a small admin set. Monitor PVE audit logs for user creation in unexpected groups or modifications to the engine's own admin user.

### Additional Security Considerations

- Synthetic per-lease users are throwaway identities — name collisions
  are mitigated with a random suffix (8-character base32, ~40 bits
  entropy), not uniqueness guarantees enforced by Proxmox itself
- The effective privileges a lease receives are determined by the
  operator's group→role binding at the ACL path (reviewable via
  `GET /access/acl`, auditable in PVE logs). Operators should scope the
  group's ACL path as narrowly as the use case allows (e.g., bind to
  `/vms/100` not `/`) and use `propagate=false` unless recursive access
  is required. Broad paths with `propagate=true` grant the role
  recursively to everything below the path
- No native TTL enforcement on Proxmox tokens themselves — if Vault's
  revoke call is delayed or fails repeatedly, the credential stays live
  until Vault's retry succeeds. The `expire` field on the user is the
  defense-in-depth backstop for this gap. This behavior (token auth
  rejected when owning user's `expire` is past) is confirmed on PVE
  9.2.10 and covered by the canary acceptance test (assertion c).
- Audit correlation: PVE logs show "user added to group X" or "user
  deleted"; Vault logs show the lease — operators correlate via the
  synthetic userid
- `token_secret` is only ever returned once, at creation, by both
  Proxmox and Vault — plugin must not attempt to read it back or log it
