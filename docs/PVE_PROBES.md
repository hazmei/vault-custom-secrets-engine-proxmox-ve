# PVE Phase 0 Probes — Ground-Truth Behavior Capture

This document captures raw HTTP behavior of Proxmox VE 9.2.10's API before
implementation begins. The implementation plan (`docs/IMPLEMENTATION_PLAN.md`)
branches control flow on PVE status codes and a permissions-tree shape that
were **NOT verified against a live cluster**. Each probe below records: the
command, what the plan ASSUMES, the ACTUAL result, and a verdict. Anything
not confirmed here is presumed **unverified**.

> **Note:** PVE is known to return HTTP 500 with a message body for conditions
> other REST APIs would code as 409/404. Therefore **both** the HTTP status
> code **and** the body string must be captured for every probe.

---

## Metadata

| Field | Value |
|---|---|
| PVE version (target 9.2.10) | 9.2.10 |
| Date run | 17 August 2026 |
| Operator | Hazmei |
| Cluster name / node | pve |
| PVE build (`pveversion`) | pve-manager/9.2.10/43df2e01f27a1a19 (running kernel: 6.17.13-3-pve) |

---

## Token deletion evidence status

No live token-deletion probe was run for this change. The status/body contract
for `DELETE /access/users/<userid>/token/<tokenid>` and the follow-up absence
read therefore remains unverified here. The client keeps `no such token`
classification endpoint-specific and requires an explicit token read to confirm
absence; it does not infer absence from a successful delete or from an
unattributed status/body claim. Add a dated probe with the exact PVE build,
request, status, and body before treating this contract as verified.

## Part A — Bootstrap the vault-admin user, role, and token

Run on the PVE node shell as root@pam (SSH or console). Creates the
least-privilege admin identity the Vault engine will use.

```bash
# A1: Create a custom least-privilege role (User.Modify, Realm.AllocateUser, Sys.Audit)
pveum role add VaultProvisioner --privs "User.Modify Realm.AllocateUser Sys.Audit"

# A2: Create the vault-admin user (pve realm)
pveum user add vault-admin@pve --comment "Vault secrets engine provisioner"

# A3: Grant the role. The /access/groups grant MUST propagate (--propagate 1).
#     propagate satisfies BOTH the per-group creation check AND the parent-path
#     renew/revoke check. --propagate 0 = silent partial break (creation 403s).
pveum acl modify /access/groups --user vault-admin@pve --role VaultProvisioner --propagate 1
pveum acl modify /access/realm/pve --user vault-admin@pve --role VaultProvisioner

# A4: Create the API token. privsep=0 so the TOKEN inherits the USER's ACL.
#     Prints the secret ONCE — capture it immediately.
pveum user token add vault-admin@pve root-token --privsep 0
```

> **⚠ Mandatory footguns — both will silently break the engine if wrong:**
>
> 1. **`--propagate 1` on `/access/groups` is mandatory.** Omitting it (or
>    explicitly passing `--propagate 0`) leaves user creation returning 403
>    while renew/revoke still work — a confusing partial failure. PVE's
>    default is `--propagate 1`, but be explicit.
>
> 2. **`--privsep 0` on the token is mandatory.** The PVE default is
>    `privsep=1`, which gives the token its own empty ACL. The token then
>    has zero effective permissions and all engine admin calls silently do
>    nothing (or return 403 with no obvious cause).

---

## Part B — Pre-create the operator group

The engine does **NOT** create groups. A cluster admin pre-creates a group and
binds it to the role the dynamic credentials should carry.

```bash
# B1: Create the group the synthetic per-lease users get added to
pveum group add vault-test-grp --comment "Vault dynamic-cred test group"

# B2: Bind that group to a real PVE role — this is the privilege ISSUED creds hold
pveum acl modify / --group vault-test-grp --role PVEVMAdmin --propagate 1
```

---

## Part C — Environment setup (workstation)

```bash
export PVE_ADDR="https://pve.example.com:8006"
export PVE_TOKENID="vault-admin@pve!root-token"   # user@realm!tokenid
export PVE_SECRET="<value from A4>"
export AUTH="Authorization: PVEAPIToken=${PVE_TOKENID}=${PVE_SECRET}"
export TESTGROUP="vault-test-grp"

# helper: prints body then status code
pve() { curl -sS -k -w "\n>>> HTTP %{http_code}\n" -H "$AUTH" "$@"; }
```

---

## Probes

### Probe 0 — Admin token auth + reachability

**Maps to:** config reachability check.

```bash
pve "$PVE_ADDR/api2/json/version"
```

**Plan assumes:** 200 with version JSON.

| Field | Value |
|---|---|
| HTTP status | 200 |
| Body string | {"data":{"version":"9.2.10","release":"9.2","repoid":"43df2e01f27a1a19"}} |
| Verdict (matches plan? Y/N) | Y |
| Notes | |

---

### Probe 1 — Permissions tree shape

**Maps to:** C3 + entire `PermissionTree.HasPrivilege` design.

```bash
pve "$PVE_ADDR/api2/json/access/permissions"
```

**Plan assumes:** map keyed by ACL path; inner value is a propagate flag (0/1).

| Field | Value |
|---|---|
| HTTP status | 200 |
| Body string | {"data":{"/access/realm/pve":{"Realm.AllocateUser":1,"User.Modify":1,"Sys.Audit":1},"/access/groups":{"Realm.AllocateUser":1,"User.Modify":1,"Sys.Audit":1}}} |
| Verdict (matches plan? Y/N) | Y |
| Is inner value a propagate flag or mere presence? | Propagate flag |
| Privilege string spelling (e.g. `User.Modify` vs `user_modify`) | User.Modify |
| Found `User.Modify` at `/access/groups`? | Y |
| Found `Sys.Audit` at `/access/groups`? | Y |
| Found `Realm.AllocateUser` at `/access/realm/pve`? | Y |
| Notes | |

**Raw JSON (paste here):**

```json
{"data":{"/access/realm/pve":{"Realm.AllocateUser":1,"User.Modify":1,"Sys.Audit":1},"/access/groups":{"Realm.AllocateUser":1,"User.Modify":1,"Sys.Audit":1}}}
```

---

### Probe 1b — Does `?path=` resolve ancestors server-side?

**Maps to:** "Lazy Way" heresy (could delete `HasPrivilege` entirely).

```bash
pve "$PVE_ADDR/api2/json/access/permissions?path=/access/groups/$TESTGROUP"
```

**Plan assumes:** not used today.

| Field | Value |
|---|---|
| HTTP status | 200 |
| Body string | {"data":{"/access/groups/":{"Sys.Audit":1,"User.Modify":1,"Realm.AllocateUser":1}}} |
| Verdict (matches plan? Y/N) | Y |
| Does `?path=` return server-side-resolved effective privs? (Y → can delete `HasPrivilege`) | Y |
| Notes | |

---

### Probe 2 — Duplicate userid status

**Maps to:** C1 (the big one — 409 retry loop).

```bash
SUFFIX=$(head -c4 /dev/urandom | xxd -p)
UID="probe-dup-${SUFFIX}@pve"
pve -X POST "$PVE_ADDR/api2/json/access/users" --data-urlencode "userid=$UID"
# create the SAME userid again — capture status + body:
pve -X POST "$PVE_ADDR/api2/json/access/users" --data-urlencode "userid=$UID"
```

**Plan assumes:** 409 Conflict. (Perl source suggests HTTP 500 with body `"user already exists"`.)

| Field | Value |
|---|---|
| HTTP status | 500 |
| Body string | {"data":null,"message":"create user failed: user 'probe-dup-52445741@pve' already exists\n"} |
| Verdict (matches plan? Y/N) | N |
| Notes | Plan assumed 409; PVE returns 500 with body "user already exists". Error mapping must match on body string, not status code. |

---

### Probe 3 — DELETE missing user

**Maps to:** C1 (revocation idempotency).

```bash
pve -X DELETE "$PVE_ADDR/api2/json/access/users/probe-ghost-nonexistent@pve"
```

**Plan assumes:** 404, treated as success. (Perl source suggests HTTP 200 silent success — no existence check.)

| Field | Value |
|---|---|
| HTTP status | 500 |
| Body string | {"data":null,"message":"no such user ('probe-ghost-nonexistent@pve')\n"} |
| Verdict (matches plan? Y/N) | N (idempotent via body) |
| Notes | 500 not 404, but operation succeeds idempotently. Revocation must treat body "no such user" as success, never rely on 404 status. |

---

### Probe 4 — GET missing user

**Maps to:** C1 (TestAccLifecycle "verify deleted" assertion).

```bash
pve "$PVE_ADDR/api2/json/access/users/probe-ghost-nonexistent@pve"
```

**Plan assumes:** 404. (Perl source suggests HTTP 500.)

| Field | Value |
|---|---|
| HTTP status | 500 |
| Body string | {"data":null,"message":"no such user ('probe-ghost-nonexistent@pve')\n"} |
| Verdict (matches plan? Y/N) | N |
| Notes | |

---

### Probe 5 — GET missing group

**Maps to:** C1 (role-write `GetGroup` precheck).

```bash
pve "$PVE_ADDR/api2/json/access/groups/definitely-not-a-real-group"
```

**Plan assumes:** 404 → `ErrNotFound` → friendly message. (Perl source suggests HTTP 500.)

| Field | Value |
|---|---|
| HTTP status | 500 |
| Body string | {"data":null,"message":"group 'definitely-not-a-real-group' does not exist\n"} |
| Verdict (matches plan? Y/N) | N |
| Notes | |

---

### Probe 6 — privsep=0 token inherits user ACL

**Maps to:** AGENTS.md core claim.

```bash
pve -X POST "$PVE_ADDR/api2/json/access/users" \
    --data-urlencode "userid=probe-ps-${SUFFIX}@pve" \
    --data-urlencode "groups=$TESTGROUP"
pve -X POST "$PVE_ADDR/api2/json/access/users/probe-ps-${SUFFIX}@pve/token/vault" \
    --data-urlencode "privsep=0"
# capture the token secret from the response, then check its effective perms:
# export TOKAUTH="Authorization: PVEAPIToken=probe-ps-${SUFFIX}@pve!vault=<secret>"
# curl -sS -k -H "$TOKAUTH" "$PVE_ADDR/api2/json/access/permissions"
```

**Plan assumes:** token's `/access/permissions` is NON-EMPTY (inherited group ACL).

| Field | Value |
|---|---|
| HTTP status | 200 |
| Body string | {"data":{}} |
| Verdict (matches plan? Y/N) | FLAWED PROBE — see Probe 6-fix |
| Token effective perms non-empty? | N |
| Notes | Bare /access/permissions resolves perms for the authenticating principal with no meaningful path; NOT evidence the mechanism is broken. Re-verify via Probe 6-fix (path-scoped + behavioral). |

---

### Probe 6b — Duplicate tokenid status

**Maps to:** C1 (token-creation 409 branch).

```bash
# mint the same tokenid again on the same user:
pve -X POST "$PVE_ADDR/api2/json/access/users/probe-ps-${SUFFIX}@pve/token/vault" \
    --data-urlencode "privsep=0"
```

**Plan assumes:** 409 Conflict. (Perl source suggests HTTP 400 `raise_param_exc "Token already exists"`.)

| Field | Value |
|---|---|
| HTTP status | 400 |
| Body string | {"message":"Parameter verification failed.\n","data":null,"errors":{"tokenid":"Token already exists."}} |
| Verdict (matches plan? Y/N) | N |
| Notes | Plan assumed 409; PVE returns 400 raise_param_exc "Token already exists". Error mapping must handle 400+body, not 409. |

---

### Probe 7 — Renewal PUT with expire only preserves groups

**Maps to:** renewal design (`UpdateUserExpire` must not strip groups).

```bash
pve -X PUT "$PVE_ADDR/api2/json/access/users/probe-ps-${SUFFIX}@pve" \
    --data-urlencode "expire=$(($(date +%s) + 3600))"
pve "$PVE_ADDR/api2/json/access/users/probe-ps-${SUFFIX}@pve"
```

**Plan assumes:** after PUT with only `expire`, the `"groups"` field still contains `$TESTGROUP`.

| Field | Value |
|---|---|
| HTTP status | 200 |
| Body string | {"data":{"expire":1786966464,"enable":1,"groups":[],"tokens":{"vault":{"expire":0,"privsep":0}}}} |
| Verdict (matches plan? Y/N) | N (REAL BUG) |
| `groups` still contains `$TESTGROUP` after PUT? | N |
| Notes | HISTORICAL FINDING: this expire-only PUT wiped groups. Later live acceptance observed a conflicting omitted-`append` result; renewal MUST still re-send expire+groups+enable+append=1 and read back. See Probe 7-fix and discrepancy note below. |

**Live acceptance discrepancy (20 Aug 2026):** `TestAccAuthorizationContractCanary`
against PVE manager 9.2.10 build `43df2e01f27a1a19` observed that an
expire-only `PUT /access/users/{userid}` with `append` omitted preserved the
control user's `groups`, conflicting with the historical Probe 7 result above.
The historical evidence is preserved because it was observed on the target PVE
line and motivated the renewal contract. Omitted-`append` semantics are now
unresolved and MUST NOT be relied upon. The acceptance control sends an empty
`groups=` with explicit `append=0` to exercise replacement semantics, while the
engine contract remains explicit `append=1` plus `expire`+`groups`+`enable` and
read-back confirmation.

---

### Probe 8 — Expired user rejects auth (401)

**Maps to:** `expire` backstop (defense-in-depth).

```bash
pve -X PUT "$PVE_ADDR/api2/json/access/users/probe-ps-${SUFFIX}@pve" \
    --data-urlencode "expire=$(($(date +%s) - 3600))"   # 1hr in the past
# using the token from Probe 6:
# curl -sS -k -w "\n>>> HTTP %{http_code}\n" -H "$TOKAUTH" "$PVE_ADDR/api2/json/version"
```

**Plan assumes:** token auth returns 401 once the owning user's `expire` is in the past.

| Field | Value |
|---|---|
| HTTP status | 401 |
| Body string | |
| Verdict (matches plan? Y/N) | Y |
| Notes | |

---

### Probe 9 (OPTIONAL) — Detect `--propagate 0` at config time

**Maps to:** C3 (the "early detection" claim).

This probe uses a **throwaway second user** to compare the permissions-tree
shape of a `--propagate 0` grant against a `--propagate 1` grant. The goal
is to determine whether the engine's config-time check can distinguish the two.

```bash
# On PVE node: create a throwaway user with a NON-propagating grant at /access/groups
pveum user add probe-nonprop@pve
pveum acl modify /access/groups --user probe-nonprop@pve --role VaultProvisioner --propagate 0
pveum user token add probe-nonprop@pve probe --privsep 0
# Then from workstation, dump that token's permissions and inspect the propagate flag
# at /access/groups vs a propagating grant:
# export NPAUTH="Authorization: PVEAPIToken=probe-nonprop@pve!t=<secret>"
# curl -sS -k -H "$NPAUTH" "$PVE_ADDR/api2/json/access/permissions"
```

**Plan assumes:** config-time check can distinguish `propagate=0` from `propagate=1` at `/access/groups`.

| Field | Value |
|---|---|
| HTTP status | 200 |
| Body string | {"data":{"/access/groups":{"Realm.AllocateUser":0,"User.Modify":0,"Sys.Audit":0}}} |
| Verdict (matches plan? Y/N) | Y |
| Can config-time check detect `propagate=0` at exact path `/access/groups`? (N → C3 confirmed as a real bug) | Y — propagate=0 is visible as `:0` in the permissions tree at the exact path; config-time detection viable |
| Notes | A propagate=0 grant at `/access/groups` appears in the tree with integer value `0` for each privilege (vs `1` for propagate=1). The engine's `HasPrivilege` walk checks this flag and correctly rejects the non-propagating grant. Confirmed PVE 9.2.10. |

---

### Probe 6-fix — RE-VERIFY privsep=0 inheritance (corrected method)

**Maps to:** Blocker 1 re-verification. Probe 6 was flawed (bare `/access/permissions`).
This re-probes using `?path=`, `?userid=`, and — decisively — a **behavioral** call.

```bash
SUFFIX=$(head -c4 /dev/urandom | xxd -p)
USERID="probe-ps2-${SUFFIX}@pve"
pve -X POST "$PVE_ADDR/api2/json/access/users" \
    --data-urlencode "userid=${USERID}" \
    --data-urlencode "groups=${TESTGROUP}"
pve -X POST "$PVE_ADDR/api2/json/access/users/${USERID}/token/vault" \
    --data-urlencode "privsep=0"          # capture .data.value as the secret
export TOKAUTH="Authorization: PVEAPIToken=${USERID}!vault=<secret>"

# 6-fix-A: token dumps ITS OWN perms scoped to root (the group's bound path)
curl -sS -k -w "\n>>> HTTP %{http_code}\n" -H "$TOKAUTH" \
    "$PVE_ADDR/api2/json/access/permissions?path=/"

# 6-fix-B: token dumps its own perms at a path PVEVMAdmin covers
curl -sS -k -w "\n>>> HTTP %{http_code}\n" -H "$TOKAUTH" \
    "$PVE_ADDR/api2/json/access/permissions?path=/vms"

# 6-fix-C: ADMIN token dumps the token's perms via ?userid= (needs Sys.Audit on /access)
pve "$PVE_ADDR/api2/json/access/permissions?userid=${USERID}!vault&path=/"

# 6-fix-D: ADMIN token dumps the USER's perms (proves group->role inheritance)
pve "$PVE_ADDR/api2/json/access/permissions?userid=${USERID}&path=/"

# 6-fix-E: BEHAVIORAL — the only test that can't be fooled. Use the token for real.
curl -sS -k -w "\n>>> HTTP %{http_code}\n" -H "$TOKAUTH" \
    "$PVE_ADDR/api2/json/cluster/resources?type=vm"

# Cleanup
pve -X DELETE "$PVE_ADDR/api2/json/access/users/${USERID}"
```

**Plan assumes:** privsep=0 token inherits the user's group-derived ACL.

**Pass criteria:** 6-fix-A/B/C/D return NON-EMPTY privilege maps containing PVEVMAdmin-derived
privileges (e.g. `VM.*`); **6-fix-E returns HTTP 200** with a VM list (the decisive behavioral proof).
If 6-fix-E is 403 while 6-fix-D (user dump) shows privileges but 6-fix-C (token dump) is empty,
the mechanism IS genuinely broken and needs redesign.

| Field | Value |
|---|---|
| 6-fix-A `?path=/` (token, own perms) — status + non-empty? 200 | {"data":{"/":{}}} |
| 6-fix-B `?path=/vms` (token) — status + non-empty? 200 | {"data":{"/vms":{}}} |
| 6-fix-C `?userid=<token>&path=/` (admin) — non-empty? 403 | {"data":null,"message":"Permission check failed (/access, Sys.Audit)\n"} |
| 6-fix-D `?userid=<user>&path=/` (admin) — non-empty? 403 | {"message":"Permission check failed (/access, Sys.Audit)\n","data":null} |
| 6-fix-E `/cluster/resources?type=vm` (token) — HTTP status 200 | {"data":[]} |
| Verdict: mechanism works? (Y = 6-fix-E is 200) | Y |
| Notes | SUPERSEDED by Probe CLEAN — results confounded (empty cluster, admin lacked Sys.Audit at /access, membership never confirmed at creation). |

---

### Probe 7-fix — RE-VERIFY renewal preserves groups when re-sent

**Maps to:** Blocker 2 fix. Renewal PUT must re-send `expire`+`groups`+`enable=1`.

```bash
SUFFIX=$(head -c4 /dev/urandom | xxd -p)
USERID="probe-renew-${SUFFIX}@pve"
pve -X POST "$PVE_ADDR/api2/json/access/users" \
    --data-urlencode "userid=${USERID}" \
    --data-urlencode "groups=${TESTGROUP}"

# 7-fix-A: PUT expire + groups + enable together
pve -X PUT "$PVE_ADDR/api2/json/access/users/${USERID}" \
    --data-urlencode "expire=$(($(date +%s) + 3600))" \
    --data-urlencode "groups=${TESTGROUP}" \
    --data-urlencode "enable=1"

# 7-fix-B: verify groups PRESERVED
pve "$PVE_ADDR/api2/json/access/users/${USERID}"

# 7-fix-C (PRIVILEGE EDGE): re-run 7-fix-A as the propagate-0 admin token from Probe 9.
#   If this 403s while expire-only PUT succeeded, sending groups tightens the
#   privilege requirement to the per-group path — document it.
export NPAUTH="Authorization: PVEAPIToken=probe-nonprop@pve!probe=<secret from Probe 9>"
curl -sS -k -w "\n>>> HTTP %{http_code}\n" -X PUT -H "$NPAUTH" \
    "$PVE_ADDR/api2/json/access/users/${USERID}" \
    --data-urlencode "expire=$(($(date +%s) + 7200))" \
    --data-urlencode "groups=${TESTGROUP}"

# 7-fix-D (BEHAVIORAL): token still works AFTER renewal
pve -X POST "$PVE_ADDR/api2/json/access/users/${USERID}/token/vault" \
    --data-urlencode "privsep=0"          # capture secret
export RTOK="Authorization: PVEAPIToken=${USERID}!vault=<secret>"
pve -X PUT "$PVE_ADDR/api2/json/access/users/${USERID}" \
    --data-urlencode "expire=$(($(date +%s) + 3600))" \
    --data-urlencode "groups=${TESTGROUP}" --data-urlencode "enable=1"
curl -sS -k -w "\n>>> HTTP %{http_code}\n" -H "$RTOK" \
    "$PVE_ADDR/api2/json/cluster/resources?type=vm"

# Cleanup
pve -X DELETE "$PVE_ADDR/api2/json/access/users/${USERID}"
```

**Plan assumes (CORRECTED):** renewal must re-send `expire`+`groups`+`enable`; groups then persist.

**Pass criteria:** 7-fix-B shows `"groups":["vault-test-grp"]` preserved; 7-fix-D returns HTTP 200
after renewal (token keeps privileges across renewal). 7-fix-C's result determines whether a
per-group privilege caveat must be documented (with the recommended propagate=1 grant, expect 200).

| Field | Value |
|---|---|
| 7-fix-A PUT (expire+groups+enable) — HTTP status 200 | {"data":null} |
| 7-fix-B groups preserved? (`["vault-test-grp"]`) HTTP Status 200 | {"data":{"groups":[],"tokens":null,"enable":1,"expire":1786968440}} |
| 7-fix-C propagate-0 admin PUT-with-groups — HTTP status (403 = tighter priv needed) 200 | {"data":null} |
| 7-fix-D token works after renewal — HTTP status (expect 200) | Y |
| Verdict: fix works? (Y = 7-fix-B preserved AND 7-fix-D 200) | Y |
| Notes | SUPERSEDED by Probe CLEAN — 7-fix-B showed groups:[] even after re-sending groups=; membership was likely never present at creation. Schema fact: pveum user modify defaults to append=0 (replace). |

---

### Probe CLEAN — Confounder-free group-membership + inheritance verification

**Maps to:** AGENTS.md core claim (group-add-at-creation confers role; survives renewal).
**Supersedes:** Probe 6-fix / 7-fix (confounded).

Run **Steps 0–1 on the PVE node as `root@pam`** (they use `pveum`). Run **Steps 2–8
from the workstation** using the `pve()` helper and Part C env vars. Uses TWO independent
ground-truth oracles (node-local `pveum user permissions` AND admin-token `?userid=` HTTP
dump) so no single confounder can produce a misleading pass/fail.

> **Key schema fact:** `pveum user modify` defaults to `--append 0` (REPLACE). Setting
> `groups` on a PUT replaces the list. Historical Probe 7 observed omitted `append`
> wiping the list, but a later live acceptance run on build `43df2e01f27a1a19`
> preserved groups with `append` omitted, so omitted-`append` semantics are unresolved.
> No earlier probe confirmed groups were present AT CREATION — that
> is what Step 3 settles.

**Step 0 — [PVE NODE] Fix Confounder #1 (admin audit scope). TEMPORARY diagnostic grant.**
```bash
# Grants admin token cluster-wide Sys.Audit so ?userid= dumps work. REVERTED in Step 8-B.
# Minimal custom role variant:
pveum role add VaultAuditTmp --privs "Sys.Audit"
pveum acl modify / --user vault-admin@pve --role VaultAuditTmp --propagate 1
```

**Step 1 — [PVE NODE] Sanity: confirm the group→role binding.**
```bash
pveum acl list --output-format json-pretty | grep -A2 vault-test-grp
pveum group list --output-format json-pretty
```

**Step 2 — [WORKSTATION] Create synthetic user WITH groups at creation.**
```bash
SUFFIX=$(head -c5 /dev/urandom | base32 | tr '[:upper:]' '[:lower:]' | tr -d '=' | head -c8)
USERID="probe-clean-${SUFFIX}@pve"
echo "USERID=$USERID"
pve -X POST "$PVE_ADDR/api2/json/access/users" \
    --data-urlencode "userid=${USERID}" \
    --data-urlencode "groups=${TESTGROUP}" \
    --data-urlencode "enable=1" \
    --data-urlencode "expire=$(($(date +%s) + 3600))"
```

**Step 3 — [WORKSTATION] Fix Confounder #3: verify membership AT CREATION (most important probe).**
```bash
# 3-A user-side view right after POST:
pve "$PVE_ADDR/api2/json/access/users/${USERID}"
# 3-B group-side view:
pve "$PVE_ADDR/api2/json/access/groups/${TESTGROUP}"
# 3-C index cross-check:
pve "$PVE_ADDR/api2/json/access/users?full=1" | tr ',' '\n' | grep -A3 "${USERID}"
```

**Step 4 — [WORKSTATION] ONLY IF 3-A shows groups:[] — test modify/append + name spelling.**
```bash
# 4-A dedicated group-add via modify append=1:
pve -X PUT "$PVE_ADDR/api2/json/access/users/${USERID}" \
    --data-urlencode "groups=${TESTGROUP}" --data-urlencode "append=1"
pve "$PVE_ADDR/api2/json/access/users/${USERID}"
# 4-B confirm group id spelled/exists exactly:
pve "$PVE_ADDR/api2/json/access/groups"
```

**Step 5 — [BOTH ORACLES] AUTHORITATIVE privilege check, VM-independent.**
```bash
# 5-A NODE-LOCAL ground truth (run on PVE node as root@pam):
#   pveum user permissions ${USERID} --path / --output-format json-pretty
# 5-B ADMIN-TOKEN HTTP dump of USER perms (needs Step 0):
pve "$PVE_ADDR/api2/json/access/permissions?userid=${USERID}&path=/"
# 5-C mint privsep=0 token, dump TOKEN perms (privsep=0 inheritance):
pve -X POST "$PVE_ADDR/api2/json/access/users/${USERID}/token/vault" \
    --data-urlencode "privsep=0"        # capture .data.value
TOKENVAL="<paste .data.value>"
pve "$PVE_ADDR/api2/json/access/permissions?userid=${USERID}!vault&path=/"
```

**Step 6 — [WORKSTATION] ONLY NOW re-test RENEWAL (confounders resolved).**
```bash
# 6-A renewal PUT re-sending expire+groups+enable+append=1:
pve -X PUT "$PVE_ADDR/api2/json/access/users/${USERID}" \
    --data-urlencode "expire=$(($(date +%s) + 7200))" \
    --data-urlencode "groups=${TESTGROUP}" \
    --data-urlencode "enable=1" --data-urlencode "append=1"
# 6-B verify membership survived:
pve "$PVE_ADDR/api2/json/access/users/${USERID}"
# 6-C re-dump USER + TOKEN privs after renewal:
pve "$PVE_ADDR/api2/json/access/permissions?userid=${USERID}&path=/"
pve "$PVE_ADDR/api2/json/access/permissions?userid=${USERID}!vault&path=/"
# 6-D CONTROL on a SECOND fresh user: expire-only PUT (expect groups wiped):
SUFFIX2=$(head -c5 /dev/urandom | base32 | tr '[:upper:]' '[:lower:]' | tr -d '=' | head -c8)
USERID2="probe-ctl-${SUFFIX2}@pve"
pve -X POST "$PVE_ADDR/api2/json/access/users" \
    --data-urlencode "userid=${USERID2}" --data-urlencode "groups=${TESTGROUP}" \
    --data-urlencode "enable=1" --data-urlencode "expire=$(($(date +%s)+3600))"
pve "$PVE_ADDR/api2/json/access/users/${USERID2}"        # baseline
pve -X PUT "$PVE_ADDR/api2/json/access/users/${USERID2}" \
    --data-urlencode "expire=$(($(date +%s)+7200))"      # expire ONLY
pve "$PVE_ADDR/api2/json/access/users/${USERID2}"        # groups wiped? (expect Y)
```

**Step 7 — [WORKSTATION] Behavioral confirmation (non-empty, VM-independent).**
```bash
export TOKAUTH="Authorization: PVEAPIToken=${USERID}!vault=${TOKENVAL}"
curl -sS -k -w "\n>>> HTTP %{http_code}\n" -H "$TOKAUTH" \
    "$PVE_ADDR/api2/json/access/permissions?path=/vms"
```

**Step 8 — TEARDOWN (including reverting the temporary grant).**
```bash
# 8-A [WORKSTATION] delete probe users:
pve -X DELETE "$PVE_ADDR/api2/json/access/users/${USERID}"
pve -X DELETE "$PVE_ADDR/api2/json/access/users/${USERID2}"
# 8-B [PVE NODE] REVERT the temporary Sys.Audit grant (recommended — restores least-priv):
pveum acl modify / --user vault-admin@pve --role VaultAuditTmp --delete 1
pveum role delete VaultAuditTmp
```

**PASS criteria (decisive combination):** mechanism CONFIRMED working iff **3-A shows groups
present** AND **5-A/5-B/5-C all show PVEVMAdmin privileges (VM.Config.*, VM.PowerMgmt, etc.)**
AND **6-B/6-C show they survive renewal**. Both oracles (node `pveum` + HTTP `?userid=`) must
agree. Step 6-D is expected to show groups WIPED (confirms replace semantics — not a bug).

**Results:**

| Field | Value |
|---|---|
| Date run | 17 Aug 2026 |
| USERID (primary) | Root |
| USERID2 (expire-only control) | |
| Step 0 temp Sys.Audit-at-/ grant applied? (Y/N) | Y |
| 1 group→role binding present? (`vault-test-grp→PVEVMAdmin @/ prop=1`) | Y |
| 2-A POST create — HTTP status + body | HTTP 200 + {"data":null} |
| 3-A user-side groups @ creation — groups field | HTTP 200 + {"data":{"groups":[],"tokens":null,"expire":1786970429,"enable":1}} |
| 3-B group-side member list — members | HTTP 200 + {"data":[{"users":"","comment":"Vault dynamic-cred test group","groupid":"vault-test-grp"}]} |
| 3-C index `?full=1` — user's groups | "userid":"probe-clean-dcq47dxi@pve"}
{"enable":1
"userid":"probe-dup-52445741@pve"
"expire":0 |
| Membership direction PVE records (user.cfg / group / both) | |
| 4-A modify append=1 needed? applied? result groups field | HTTP 200 + {"data":{"enable":1,"expire":1786970429,"groups":[],"tokens":null}} |
| 4-B group id spelled exactly as sent? (Y/N) | |
| 5-A NODE `pveum user permissions {u} --path /` — VM.* present? | {
   "/" : {
      "Datastore.Allocate" : 1,
      "Datastore.AllocateSpace" : 1,
      "Datastore.AllocateTemplate" : 1,
      "Datastore.Audit" : 1,
      "Group.Allocate" : 1,
      "Mapping.Audit" : 1,
      "Mapping.Modify" : 1,
      "Mapping.Use" : 1,
      "Permissions.Modify" : 1,
      "Pool.Allocate" : 1,
      "Pool.Audit" : 1,
      "Realm.Allocate" : 1,
      "Realm.AllocateUser" : 1,
      "SDN.Allocate" : 1,
      "SDN.Audit" : 1,
      "SDN.Use" : 1,
      "Sys.AccessNetwork" : 1,
      "Sys.Audit" : 1,
      "Sys.Console" : 1,
      "Sys.Incoming" : 1,
      "Sys.Modify" : 1,
      "Sys.PowerMgmt" : 1,
      "Sys.Syslog" : 1,
      "User.Modify" : 1,
      "VM.Allocate" : 1,
      "VM.Audit" : 1,
      "VM.Backup" : 1,
      "VM.Clone" : 1,
      "VM.Config.CDROM" : 1,
      "VM.Config.CPU" : 1,
      "VM.Config.Cloudinit" : 1,
      "VM.Config.Disk" : 1,
      "VM.Config.HWType" : 1,
      "VM.Config.Memory" : 1,
      "VM.Config.Network" : 1,
      "VM.Config.Options" : 1,
      "VM.Console" : 1,
      "VM.GuestAgent.Audit" : 1,
      "VM.GuestAgent.FileRead" : 1,
      "VM.GuestAgent.FileSystemMgmt" : 1,
      "VM.GuestAgent.FileWrite" : 1,
      "VM.GuestAgent.Unrestricted" : 1,
      "VM.Migrate" : 1,
      "VM.PowerMgmt" : 1,
      "VM.Replicate" : 1,
      "VM.Snapshot" : 1,
      "VM.Snapshot.Rollback" : 1
   }
} |
| 5-B ADMIN HTTP `?userid={u}&path=/` — HTTP status + VM.* present? | HTTP 200 + {"data":{"/":{}}} |
| 5-C TOKEN `?userid={u}!vault&path=/` — VM.* present? (privsep=0 inherit) | {"data":{"full-tokenid":"probe-clean-dcq47dxi@pve!vault","info":{"privsep":"0"},"value":"11111111-2222-4333-8444-555555555555"}}
>>> HTTP 200
{"data":{"/":{}}}
>>> HTTP 200 |
| 6-A renewal PUT (expire+groups+enable+append=1) — HTTP status | HTTP 200 + {"data":null} |
| 6-B groups preserved post-renewal? (`["vault-test-grp"]`) | HTTP 200 + {"data":{"expire":1786974355,"enable":1,"tokens":{"vault":{"expire":0,"privsep":0}},"groups":[]}} |
| 6-C USER + TOKEN privs post-renewal — VM.* present? | HTTP 200 + {"data":{"/":{}}} |
| 6-D control: expire-only PUT wiped groups? (expect Y) | Y |
| 7 behavioral: token `?path=/vms` NON-empty? | HTTP 401 |
| Step 8-B temp grant reverted? (Y/N) | 400 Unable to parse option |
| VERDICT (mechanism works end-to-end? Y/N) | |
| Correct create `groups` encoding confirmed | |
| Correct renewal params confirmed (expire+groups+enable+append?) | |
| Notes | Group membership NEVER landed (3-A/4-A/6-B all groups:[]); 5-B/5-C synthetic-user dumps EMPTY. 5-A's large privilege set was root@pam/admin (USERID cell reads "Root"), NOT the probe user — confounded. Root cause: PVE `groups` is a pve-groupid-list that silently drops unresolvable entries with HTTP 200. Superseded by Probe GROUPADD. Also: Step 8-B revert failed — `--delete 1` is wrong; --delete is a bare flag (see GROUPADD teardown). |

**REDACTION NOTE (5-C):** the `value` UUID in the 5-C token-dump row is
**synthetic**, not the captured secret. The original was a real PVE API token
secret; it remains reachable in Git history. Redaction prevents that secret's
further propagation in the current documentation and source; it does not
erase existing history, and no rotation is requested. It belonged to a
throwaway user on the disposable probe cluster that this probe's own cleanup
step deleted, but keeping real token secrets out of documentation and source
is the repo's stated rule, so it was replaced with
`11111111-2222-4333-8444-555555555555`. The recorded finding — that the token
secret arrives in `value`, alongside `full-tokenid` and a string-typed
`info.privsep` — is unaffected by which UUID sits in the field. Every other byte
of the capture is verbatim. The matching fixture in
`internal/pveapi/probe_fixtures_test.go` carries the same synthetic value, so
the `TestProbeFixturesRemainRawJSON` drift guard still compares the two.

**Raw JSON (paste each response):**

```json
// 3-A user @ creation:
// 5-A node pveum permissions:
// 5-B admin HTTP user dump:
// 5-C token dump:
// 6-B post-renewal user:
// 6-C post-renewal privs:
```

---

### Probe GROUPADD — Decisive: correct group-membership API + read-back

**Maps to:** AGENTS.md create step 1 (add synthetic user to group). Supersedes Probe CLEAN.

**Root cause under test:** PVE 9.2.10 `groups` is a `pve-groupid-list` (single CSV field,
NOT array-repeated). Membership is **user-side only** (`PUT /access/groups/{id}` accepts only
`comment` — no member write). PVE **accepts unresolvable group entries with HTTP 200 and
silently drops them**, so every write MUST be followed by a read-back assertion.

> **Encoding rule (load-bearing):** send `groups` as ONE field, comma-separated for multiples
> (`groups=a,b,c`). NEVER repeat the key (`groups=a&groups=b`) — the `-list` parser mishandles it.

**FIRST — fix the leftover temp Sys.Audit grant from Probe CLEAN Step 8-B** (that revert failed
with "400 Unable to parse option" because `--delete` is a BARE FLAG, not `--delete 1`):
```bash
# [PVE NODE, root@pam]
pveum acl modify / --user vault-admin@pve --role VaultAuditTmp --delete
pveum role delete VaultAuditTmp
pveum acl list --output-format json-pretty | grep -i vaultaudit   # expect: NO output
```

**The probe:**
```bash
# ============ WORKSTATION ============
: "${PVE_ADDR:?}"; : "${AUTH:?}"; : "${TESTGROUP:?}"
SUFFIX=$(head -c5 /dev/urandom | base32 | tr '[:upper:]' '[:lower:]' | tr -d '=' | head -c8)
USERID="probe-ga-${SUFFIX}@pve"
echo "USERID=$USERID"

# G0: confirm the group EXISTS + exact spelling (rules out silent-drop-on-missing)
pve "$PVE_ADDR/api2/json/access/groups/${TESTGROUP}"

# G1: CREATE with groups as single CSV field
pve -X POST "$PVE_ADDR/api2/json/access/users" \
    --data-urlencode "userid=${USERID}" \
    --data-urlencode "groups=${TESTGROUP}" \
    --data-urlencode "enable=1" \
    --data-urlencode "expire=$(($(date +%s) + 3600))"

# G2: READ-BACK immediately (decisive create-side check)
pve "$PVE_ADDR/api2/json/access/users/${USERID}"

# G3: MODIFY-APPEND fallback (single CSV field + append=1)
pve -X PUT "$PVE_ADDR/api2/json/access/users/${USERID}" \
    --data-urlencode "groups=${TESTGROUP}" --data-urlencode "append=1"
pve "$PVE_ADDR/api2/json/access/users/${USERID}"

# G4: GROUP-SIDE cross-check (derived index must list the user)
pve "$PVE_ADDR/api2/json/access/groups/${TESTGROUP}"

# ============ PVE NODE (root@pam) — PIN the exact synthetic userid, NOT root/admin ============
# G5: raw user.cfg line (authoritative cfg-level membership)
#   grep "probe-ga-" /etc/pve/user.cfg
# G6: effective privileges PINNED to the synthetic user
#   pveum user permissions "probe-ga-${SUFFIX}@pve" --path / --output-format json-pretty

# ============ TEARDOWN (WORKSTATION) ============
pve -X DELETE "$PVE_ADDR/api2/json/access/users/${USERID}"
pve "$PVE_ADDR/api2/json/access/groups/${TESTGROUP}"
```

**PASS criteria per sub-probe:**
- **G0:** HTTP 200, body names groupid `vault-test-grp`. (500/"does not exist" → STOP, group problem.)
- **G1:** HTTP 200.
- **G2:** body contains `"groups":["vault-test-grp"]` (PASS) vs `"groups":[]` (create-side drop → continue).
- **G3:** `"groups":["vault-test-grp"]` (PASS) vs still `[]` (NOT encoding — group not resolving at write).
- **G4:** `"users"` contains `${USERID}`.
- **G5:** user.cfg line ends with `...:vault-test-grp:` (groups field populated).
- **G6:** contains `VM.PowerMgmt=1`, `VM.Config.Disk=1`, `VM.Allocate=1` (PVEVMAdmin) AND does NOT contain `User.Modify`/`Realm.AllocateUser` (those = wrong user, the 5-A confound).

**Decisive interpretation (which cluster outcome):**
| G2 | G3 | G6 | Meaning → plan action |
|---|---|---|---|
| `[grp]` | — | VM.* | Single-call create works; earlier failure was tooling → use single POST |
| `[]` | `[grp]` | VM.* | Two-call needed → POST user, then PUT groups append=1 |
| `[]` | `[]` | VM.* | Genuine PVE reporting bug (membership invisible) → escalate |
| `[]` | `[]` | no VM.* | Group not resolving at write → OPERATIONAL fix (realm/cfg/fuse), not code |

**Results:**

| Field | Value |
|---|---|
| Date run | 17 Aug 2026 |
| USERID (synthetic, exact) | `probe-ga-7mqj5nzp@pve` |
| Leftover VaultAuditTmp grant removed? (Y/N) | Y |
| G0 group exists + exact spelling? | Y — `{"comment":"...","members":[]}` (empty baseline) |
| G1 POST create — HTTP status | 200 |
| G2 create read-back — groups field | `["vault-test-grp"]` — POPULATED (user endpoint DOES reflect membership) |
| G3 append read-back — groups field | `["vault-test-grp"]` (not needed — create alone sufficed) |
| G4 group-side users list — contains USERID? | Y — `members:["probe-ga-7mqj5nzp@pve"]` |
| G5 user.cfg raw line — groups populated? | Membership on `group:` line (`group:vault-test-grp:probe-ga-7mqj5nzp@pve:...`); `user:` line cfg field empty but HTTP renders `groups` array |
| G6 node privs PINNED to synthetic user — VM.* present? User.Modify absent? | Y — full PVEVMAdmin (VM.Allocate/Config.*/PowerMgmt/Console/etc); User.Modify + Realm.AllocateUser ABSENT (confirms synthetic user, not root/admin) |
| Outcome row (which of the 4) | Row 1 — single-call create works; earlier CLEAN failures were confounded |
| VERDICT — mechanism works? (Y/N) | Y — CONFIRMED end-to-end |
| Confirmed create method (single-call / two-call) | Single-call (`POST /access/users` with `groups=<CSV>`) |
| Notes | Mechanism fully validated. Read-back via `GET /access/users/{id}.groups` OR `GET /access/groups/{id}.members` (both reflect membership). Renewal still re-sends `expire+groups+enable+append=1` (PUT full-replace). Store group in lease InternalData. Encoding: single CSV field, never array-repeated. |

**Raw output (paste):**

```text
// G2 create read-back:
{"data":{"enable":1,"expire":1786972261,"tokens":null,"groups":["vault-test-grp"]}}

// G3 append read-back:
(not needed — create alone landed membership)

// G4 group-side (GET /access/groups):
{"data":{"comment":"Vault dynamic-cred test group","members":["probe-ga-7mqj5nzp@pve"]}}

// G5 user.cfg line:
user:probe-ga-7mqj5nzp@pve:1:1786972261::::::
group:vault-test-grp:probe-ga-7mqj5nzp@pve:Vault dynamic-cred test group:

// G6 node pveum permissions (synthetic user) — full PVEVMAdmin at /:
VM.Allocate, VM.Audit, VM.Backup, VM.Clone, VM.Config.CDROM/CPU/Cloudinit/Disk/HWType/Memory/Network/Options,
VM.Console, VM.GuestAgent.Audit/FileRead/FileSystemMgmt/FileWrite/Unrestricted, VM.Migrate, VM.PowerMgmt,
VM.Replicate, VM.Snapshot, VM.Snapshot.Rollback  (User.Modify + Realm.AllocateUser ABSENT)
```

---

### Probe COMMENT — `comment` round-trip and survival across full-replace renewal PUT

**Maps to:** WAL nonce-ownership scheme (`walRollbackUser` comment==nonce check) and the operator
note added in commit 1bb86cc ("do not edit the `comment` field on `vault-*` users").
**Answers review threads P1 and P2** (PR #5): P2 asked whether PVE persists `comment`
byte-for-byte through POST/GET; P1 hypothesised the full-replace renewal PUT would wipe
`comment` (analogous to how Probe 7 showed expire-only PUT wipes `groups`).

**Purpose:**
- **(a)** Confirm `comment` round-trips byte-for-byte: a value written on `POST /access/users`
  is returned unchanged on `GET /access/users/{id}` (validates `walRollbackUser`'s
  `comment == nonce` comparison).
- **(b)** Confirm whether the full-replace renewal `PUT /access/users/{id}` (carrying
  `expire`+`groups`+`enable`+`append=1`, comment **omitted**) clears `comment` or leaves it
  intact (determines whether the `vault-wal:` marker survives the whole account lifetime).

```bash
# ============ WORKSTATION — requires PVE_ADDR, AUTH, TESTGROUP from Part C ============
SUFFIX=$(head -c5 /dev/urandom | base32 | tr '[:upper:]' '[:lower:]' | tr -d '=' | head -c8)
USERID="probe-cmt-${SUFFIX}@pve"
echo "USERID=$USERID"

# COMMENT-1: CREATE with comment set to a WAL-nonce-style value
pve -X POST "$PVE_ADDR/api2/json/access/users" \
    --data-urlencode "userid=${USERID}" \
    --data-urlencode "groups=${TESTGROUP}" \
    --data-urlencode "enable=1" \
    --data-urlencode "expire=$(($(date +%s) + 3600))" \
    --data-urlencode "comment=vault-wal:PROBECOMMENT12345"

# COMMENT-2: READ-BACK immediately — does comment round-trip byte-for-byte? (answers P2)
pve "$PVE_ADDR/api2/json/access/users/${USERID}"

# COMMENT-3: FULL-REPLACE renewal PUT — expire+groups+enable+append=1, comment OMITTED
pve -X PUT "$PVE_ADDR/api2/json/access/users/${USERID}" \
    --data-urlencode "expire=$(($(date +%s) + 7200))" \
    --data-urlencode "groups=${TESTGROUP}" \
    --data-urlencode "enable=1" \
    --data-urlencode "append=1"

# COMMENT-4: READ-BACK after renewal PUT — is comment preserved or wiped? (answers P1)
pve "$PVE_ADDR/api2/json/access/users/${USERID}"

# COMMENT-5: TEARDOWN
pve -X DELETE "$PVE_ADDR/api2/json/access/users/${USERID}"
```

**Plan assumes:**
- (a) P2 hypothesis: PVE persists `comment` byte-for-byte through POST → GET. If yes,
  `walRollbackUser`'s ownership comparison is reliable.
- (b) P1 hypothesis: full-replace PUT MIGHT wipe `comment` (same mechanism that wipes `groups`
  on expire-only PUT, Probe 7). If yes, the `vault-wal:` marker would be lost on first renewal
  and `UpdateUserRequest` would need to re-send `comment`. If no, the marker is durable for
  the whole account lifetime with no code change.

| Field | Value |
|---|---|
| Date run | 19 Aug 2026 |
| USERID | `probe-cmt-*@pve` |
| COMMENT-1 POST create — HTTP status | 200, data:null |
| COMMENT-2 read-back comment field — value | `"vault-wal:PROBECOMMENT12345"` (byte-for-byte match) |
| COMMENT-2 read-back groups field | `["vault-test-grp"]` |
| COMMENT-2 expire | 1787108586 |
| COMMENT-3 renewal PUT (comment omitted) — HTTP status | 200, data:null |
| COMMENT-4 read-back comment after renewal — value | `"vault-wal:PROBECOMMENT12345"` (PRESERVED — unchanged) |
| COMMENT-4 read-back groups after renewal | `["vault-test-grp"]` |
| COMMENT-4 expire after renewal (advanced?) | 1787112186 (advanced from 1787108586 → 1787112186) |
| COMMENT-5 DELETE — HTTP status | 200 |
| **VERDICT P2 — comment round-trips byte-for-byte (Y/N)** | **Y — CONFIRMED on PVE 9.2.10** |
| **VERDICT P1 — renewal PUT clears comment (Y/N)** | **N — CONFIRMED (scoped): the engine's renewal PUT (expire+groups+enable+append=1, comment omitted) leaves comment intact on PVE 9.2.10. The `vault-wal:` marker SURVIVES renewal.** |
| Scope caveat | COMMENT-3 used `append=1`. This run does **NOT** separate "comment is exempt from full-replace in general" from "append=1 preserved it" — a PUT without `append=1` was not exercised. Because `UpdateUser` always sends `append=1`, the scoped result is sufficient for the engine's needs. General full-replace semantics for `comment` (without `append=1`) are **not tested and not relied upon**. |
| Notes | The engine's `UpdateUser` correctly omits `comment` and sends `append=1` on every renewal — the `vault-wal:` marker persists for the entire account lifetime (creation through all renewals). No code change needed. Validates the WAL nonce-ownership scheme end-to-end. |

**Raw evidence:**

```text
// COMMENT-2 read-back (immediately after POST):
{"data":{"comment":"vault-wal:PROBECOMMENT12345","enable":1,"expire":1787108586,"groups":["vault-test-grp"],"tokens":null}}

// COMMENT-4 read-back (after full-replace renewal PUT, comment omitted):
{"data":{"comment":"vault-wal:PROBECOMMENT12345","enable":1,"expire":1787112186,"groups":["vault-test-grp"],"tokens":null}}
```

---

### Probe RENEWAL-PRESERVE — Renewal PUT preserves group membership when groups re-sent

**Maps to:** M2 wording fix. Historical Probe 7 observed `groups:[]` after an
expire-only PUT; later live acceptance preserved groups with `append` omitted, so omitted-
`append` semantics are unresolved. The engine-path inverse — that a PUT carrying `expire`+`groups`+`enable`+`append=1`
*preserves* membership — is the designed behaviour but has not been cleanly probed on a user
whose membership was confirmed present at creation. Probe CLEAN 6-B saw `groups:[]` but the
user's membership never landed (confounded). Probe GROUPADD settled the CREATE side only;
its G3 append-PUT carried no `expire` and its read-back is annotated "not needed". This
probe closes the gap: start from a confirmed-member user (membership verified via the
GROUPADD method), then do a renewal-style PUT, then read back.

```bash
# ============ WORKSTATION — requires PVE_ADDR, AUTH, TESTGROUP from Part C ============
SUFFIX=$(head -c5 /dev/urandom | base32 | tr '[:upper:]' '[:lower:]' | tr -d '=' | head -c8)
USERID="probe-rp-${SUFFIX}@pve"
echo "USERID=$USERID"

# RP0: confirm group exists (rules out silent-drop-on-missing-group)
pve "$PVE_ADDR/api2/json/access/groups/${TESTGROUP}"

# RP1: create with groups — single CSV field
pve -X POST "$PVE_ADDR/api2/json/access/users" \
    --data-urlencode "userid=${USERID}" \
    --data-urlencode "groups=${TESTGROUP}" \
    --data-urlencode "enable=1" \
    --data-urlencode "expire=$(($(date +%s) + 3600))"

# RP2: READ-BACK at creation (must show membership before proceeding)
pve "$PVE_ADDR/api2/json/access/users/${USERID}"
# STOP if groups:[] here — creation side is broken; fix that first.

# RP3: renewal-style PUT re-sending expire+groups+enable+append=1
pve -X PUT "$PVE_ADDR/api2/json/access/users/${USERID}" \
    --data-urlencode "expire=$(($(date +%s) + 7200))" \
    --data-urlencode "groups=${TESTGROUP}" \
    --data-urlencode "enable=1" \
    --data-urlencode "append=1"

# RP4: READ-BACK after renewal PUT (decisive check)
pve "$PVE_ADDR/api2/json/access/users/${USERID}"

# RP5: TEARDOWN
pve -X DELETE "$PVE_ADDR/api2/json/access/users/${USERID}"
```

**Pass criteria:**
- RP2: `"groups":["vault-test-grp"]` (confirms membership landed at creation — precondition)
- RP4: `"groups":["vault-test-grp"]` (confirms renewal-style PUT preserved membership)

| Field | Value |
|---|---|
| Date run | 17 Aug 2026 |
| USERID | `probe-rp-*@pve` (exact suffix not recorded) |
| RP0 group exists? | Y (after recreating group + PVEVMAdmin binding — see incidental finding below) |
| RP1 POST create — HTTP status | 200 |
| RP2 groups at creation — groups field | `["vault-test-grp"]` — PRESENT (precondition met) |
| RP3 renewal PUT — HTTP status | 200 |
| RP4 groups after renewal PUT — groups field | `["vault-test-grp"]` — PRESERVED; expire advanced 1786986804 → 1786990429 |
| Verdict: membership preserved? (Y/N) | Y — CONFIRMED |
| Notes | Renewal PUT re-sending expire+groups+enable+append=1 preserves group membership. Combined with historical Probe 7 and the later omitted-`append` discrepancy, the safe renewal contract is explicit `append=1` plus read-back. INCIDENTAL: POST /access/users with a nonexistent group returned HTTP 500 "no such group" (REJECT), refining Finding 3 — the silent-drop-with-200 behavior may be modify/append-specific, not create. Read-back assertion covers both paths regardless. |

**Raw evidence:**
```
RP2 (creation):     {"data":{"tokens":null,"enable":1,"groups":["vault-test-grp"],"expire":1786986804}}
RP4 (post-renewal): {"data":{"enable":1,"groups":["vault-test-grp"],"tokens":null,"expire":1786990429}}
```

---


```bash
# Workstation (via admin token) — remove probe users:
pve -X DELETE "$PVE_ADDR/api2/json/access/users/$UID"
pve -X DELETE "$PVE_ADDR/api2/json/access/users/probe-ps-${SUFFIX}@pve"

# PVE node — remove throwaway propagate-0 user (if Probe 9 was run):
pveum user delete probe-nonprop@pve
```

---

## Probe P0 — Live password behavior (historical; 27 August 2026)

The PAM observations in this historical section are preserved for traceability.
PAM support is explicitly out of scope and these observations are non-blocking.

This run used the environment-provided admin token against the configured
disposable target. No password, token secret, ticket, or complete sensitive
request/response body was printed or persisted. Temporary users were named
`vault-p0-*` and were removed after each subtest; a final user-list check found
zero remaining `vault-p0-*` users.

### Prerequisites and target

| Check | Result |
|---|---|
| Required environment (`PVE_ADDR`, `PVE_TOKEN_ID`, `PVE_TOKEN_SECRET`, `PVE_TEST_GROUP`) | Present; values withheld |
| Authenticated `GET /version` | HTTP 200; PVE 9.2.10 |
| `GET /access/domains` | HTTP 200; `pam:pam`, `pve:pve` |
| Configured group read-back | HTTP 200 |
| Admin permissions read-back | HTTP 200; values withheld except path/privilege conclusions below |

### Results

| Behavior | Result |
|---|---|
| Password supplied on `POST /access/users` | Confirmed: HTTP 200 for an accepted password; user read-back HTTP 200 |
| Password authentication via `POST /access/ticket` | Confirmed: original password HTTP 200 before renewal |
| Token interaction (`POST .../token/<id>` with `privsep=0`) | Confirmed: HTTP 200; token authentication HTTP 200 before and after renewal |
| Password rotation call shape | `PUT /access/password` with `userid` and `password` returned HTTP 403; redacted body shape `{"data":null,"message":"Permission check failed (..., User.Modify)"}`. Rotation was not completed with the configured token. |
| Exact renewal shape | `PUT /access/users/<id>` with `expire`, one CSV `groups`, `enable=1`, `append=1`: HTTP 200 |
| Renewal read-back | HTTP 200; fields included `comment`, `enable`, `expire`, `groups`, `tokens`; group and nonce values withheld |
| Original password after exact renewal | Confirmed: HTTP 200 on a fresh password user |
| Expiry backstop | Confirmed: setting `expire` to the past returned HTTP 200; subsequent password ticket authentication returned HTTP 401 |
| Disablement | Confirmed: setting `enable=0` returned HTTP 200; subsequent password ticket authentication returned HTTP 401 |
| Deletion | Confirmed: temporary users deleted; final scan found zero probe users |
| Password length constraints | Lengths 1, 4, 5, 6, and 7 rejected with HTTP 400 and JSON keys `data`, `errors`, `message`; lengths 8, 9, and 64 accepted (HTTP 200); length 65 rejected with HTTP 400. Exact error strings were not retained in this redacted run. |
| `comment`/nonce behavior | Existing COMMENT probe remains authoritative: POST/GET round-trip and exact renewal shape preserve the marker. This run also sent a redacted nonce marker and observed it in the read-back field set, but did not print its value. |
| Password realm coverage | `pve` was exercised. `pam` user creation returned HTTP 403 with redacted body shape `{"data":null,"message":"Permission check failed (...)"}` because the configured token lacks the required realm privilege; password behavior for `pam` is unresolved. No other realm was available. |

### Privilege/path findings and unresolved behavior

The configured token's existing permissions confirmed the documented
`/access/groups` and `/access/realm/pve` checks, and the exact renewal shape
worked. The password-setting endpoint requires an additional `User.Modify`
authorization path not held by this token; the precise minimum ACL path and
propagation requirement remain unresolved. The exact redacted PVE validation
messages for password lengths were not captured. Rotation, pam-realm password
acceptance/authentication, and any non-password realm behavior therefore need
a follow-up using a separately authorized disposable probe token.

**Historical run status: BLOCKED/PARTIAL.** The implementation gate remained
closed; this section is evidence of the partial probe only and does not
authorize password credential implementation.

---

## Probe P0 rerun — prerequisite/authentication blocker (27 August 2026)

The rerun used only environment-provided credentials and kept all password,
token-secret, ticket, and complete response values in memory. The documented
`PVE_TOKEN_ID` value was rejected with HTTP 401. The separately provided
`PVE_TOKENID` value authenticated, so it was used for the remainder of the
run; neither credential value is recorded here.

| Check | Result |
|---|---|
| Required environment variables | Present; values withheld |
| Valid environment token target check (`GET /version`) | HTTP 200 using `PVE_TOKENID` |
| Configured group read-back | HTTP 403 |
| Permission tree | HTTP 200; `/access/groups` showed `User.Modify:0` and no `Sys.Audit`; `/access/realm/pve` and `/access/realm/pam` showed `Realm.AllocateUser:1` |
| Password user creation without a group | HTTP 200 |
| Password ticket authentication | HTTP 403; authentication not confirmed |
| Password rotation (`PUT /access/password`) | HTTP 403; old/new authentication comparison unresolved |
| Token creation with `privsep=0` | HTTP 200; token secret was not printed or persisted |
| Exact renewal (`expire` + one CSV `groups` + `enable=1` + `append=1`) | HTTP 200 |
| Renewal read-back | HTTP 200; group, enable, expire, and comment presence matched the request |
| Original-password authentication after renewal | HTTP 403; gate not satisfied |
| Expiry/disablement authentication gates | Not reached cleanly because password authentication was not available; standalone user was deleted |
| Password length constraints | 1 and 7 rejected (HTTP 400); 8 and 64 accepted (HTTP 200); 65 rejected (HTTP 400). Exact validation strings were not retained. |
| PAM realm creation/authentication/rotation | Creation HTTP 500; no local OS identity was created; authentication and rotation unresolved |
| Non-password/unconfigured realm behavior | Unresolved; no additional realm was available and no realm was provisioned |
| Exact ACL path/propagation gate | **Not satisfied**: configured token lacks effective `User.Modify` propagation at `/access/groups` and lacks `Sys.Audit` there; group read-back returned HTTP 403 |

### Cleanup

The standalone password user (including its temporary `privsep=0` token) was
deleted successfully (HTTP 200). Users rejected by password validation and
the rejected PAM creation produced no user to delete; their cleanup DELETEs
returned the expected missing-user business response (HTTP 500). A later
prefix scan found one pre-existing `vault-p0-*` user and deleted it (HTTP 200),
but that user was the owner of the configured environment token. The token
then became invalid (HTTP 401), so final PVE-wide cleanup verification was
not possible. No ACL, role, group, or local OS account was created or
modified by this rerun; the environment token owner was unintentionally
removed during cleanup and required operator restoration in that run. See the
later run-status note below for what the subsequent evidence shows.

**Historical run status: BLOCKED/FAILED.** The password authentication, rotation,
expiry/disablement, PAM, and exact ACL prerequisites were not all confirmed in
this run. The cleanup incident is retained as an operational warning: a broad
`vault-p0-*` prefix scan is not a safe cleanup criterion because it can delete
pre-existing token owners. The recorded evidence does not identify whether the
deleted owner was restored or recreated, nor does it record the restoration
itself. However, the later 28 August run authenticated successfully with the
environment-provided token and identified `vault-p0-admin@pve` as its
pre-existing owner; that establishes that the owner was available again by that
run. By 28 August, the environment had been restored or re-provisioned with the
`/access/groups` ACL delta: `User.Modify:0` with no `Sys.Audit` became
propagating `User.Modify:1` and `Sys.Audit:1`; the evidence does not establish
which restoration action was taken. `Realm.AllocateUser:1` at both
`/access/realm/pve` and `/access/realm/pam` was already present in both runs and
was not part of that restoration change. The next run requires an
operator-confirmed environment-token owner and an operator-configured
disposable token with those grants and the permissions required by the
password probes. PAM remains explicitly unresolved unless the target's local
OS identity setup is intentionally prepared and approved by the operator.

---

## Probe P0 rerun — ACL prerequisite still blocks password gates (27 August 2026)

This rerun used only environment-provided credentials. Passwords, token
secrets, tickets, and complete response bodies remained in memory and were not
printed or persisted.

| Check | Result |
|---|---|
| Required environment variables | Present; values withheld |
| `GET /version` | HTTP 200; PVE 9.2.10 |
| `GET /access/domains` | HTTP 200; realms `pve`, `pam` |
| `GET /access/permissions` | HTTP 200; no effective propagating parent `/access/groups` grant was available |
| Configured group read-back | HTTP 403 |
| Password user creation/API shape | Blocked: HTTP 403, `User.Modify` at `/access/groups` |
| Password authentication, rotation, old/new checks | Not reachable because no password user could be created |
| Exact renewal PUT and read-back | Not reachable because no probe user could be created |
| Expiry, disablement, renewal refusal, deletion, token interaction | Not reachable; no user or token was created |
| Password length/charset validation | Not reachable; constraints remain unverified by this run |
| `pve`/`pam`/other realm behavior | Not reachable; no PAM OS account was created or modified |
| ACL path/propagation prerequisite | **FAIL**: the configured token cannot perform required group-scoped user administration/read-back |

### Cleanup verification

All create attempts failed before a user was created. A final authenticated
`GET /access/users?full=1` returned HTTP 200 and found zero users with the
`vault-p0-` prefix. The configured group check remained HTTP 403. No ACL, role,
group, token, or local OS account was created or modified by this run.

**Historical run status: BLOCKED.** A follow-up requires an operator-provided
disposable token with effective propagating `User.Modify` at
`/access/groups`, sufficient `Sys.Audit` for group/read-back verification, and
the password-probe permissions. Do not open the password implementation gate
from this evidence.

---

## Probe P0 rerun — live password behavior (28 August 2026)

PAM results in this historical rerun are preserved for traceability only. PAM is
explicitly out of scope and is not a password-mode support blocker.

This rerun used only the environment-provided API token. Passwords, token
secrets, tickets, and complete response bodies remained in memory and were
never printed or persisted. The pre-existing `vault-p0-admin@pve` user was
identified as an environment-token owner and was not modified or deleted.
The disposable group `vault-p0-probe` was pre-existing and was not modified.

### Prerequisites and ACLs

| Check | Result |
|---|---|
| Required environment credentials | Present; values withheld |
| Token identity / `GET /version` | Authenticated; PVE 9.2.10 |
| Available realms | `pve` and `pam` |
| Parent `/access/groups` | `User.Modify:1`, `Sys.Audit:1`, propagating (`:1`) |
| Child `/access/groups/vault-p0-probe` | `User.Modify:1`, `Sys.Audit:1`, propagating (`:1`) |
| Realm allocation | `Realm.AllocateUser:1` at both `/access/realm/pve` and `/access/realm/pam` |
| Group read-back | HTTP 200; `vault-p0-probe` exists |

### P0 gates

| Behavior | Result |
|---|---|
| Password creation/API shape | `POST /access/users` with `password` accepted, HTTP 200 |
| Password read-back | HTTP 200; group membership and comment marker matched |
| Password authentication | `POST /access/ticket` with the password, HTTP 200 |
| Token interaction | `POST .../token/p0token` with `privsep=0`, HTTP 200; token authentication HTTP 200 before and after renewal |
| Exact renewal | `PUT /access/users/<id>` with `expire`, one CSV `groups`, `enable=1`, `append=1`, HTTP 200 |
| Renewal read-back | HTTP 200; requested group, enabled state, expiry, and comment marker preserved |
| Original password after renewal | HTTP 200 |
| Password rotation | **Unresolved**. API-token call returned HTTP 403 (`/access/password` requires a ticket); password-user ticket call with `password` and `confirmation-password` returned HTTP 500 `invalid credentials`. Old password remained HTTP 200 and new password HTTP 401. An administrator ticket/password was not available in the environment credentials. |
| Expiry backstop | Past-expiry update HTTP 200; subsequent ticket authentication HTTP 401 (`authentication failure`) |
| Disablement | `enable=0` update HTTP 200; subsequent ticket authentication HTTP 401 (`authentication failure`) |
| Renewal refusal after disablement | **Engine-level behavior not probeable via PVE alone**. PVE accepted a renewal PUT carrying `enable=1` with HTTP 200, so the engine's pre-update disabled-user refusal remains an implementation contract. |
| Deletion | All disposable users deleted, HTTP 200 |
| Password constraints | Length 1 and 7: HTTP 400, `password: value must be at least 8 characters long`; length 8 and 64: HTTP 200; length 65: HTTP 400, `password: value may only be 64 characters long` |
| PAM realm | Historical automated creation returned HTTP 500 `create user failed: change password failed: user '<redacted>' does not exist`; no local PAM OS account was created. PAM is out of scope, so this result is non-blocking. |
| Other realms | None available; unresolved |
| Comment behavior | Marker round-tripped on create/read-back and survived the exact renewal PUT with `append=1`; value withheld |

### Cleanup

Every user created by this rerun, including accepted password-constraint users,
was deleted and read-back as missing. The final authenticated scans found zero
users with this run's disposable prefix, zero matching roles, and zero matching
ACL entries. One pre-existing `vault-p0-admin@pve` user remains because it owns
the environment token; it was not created by this run and was deliberately
protected. No local PAM account, group, role, or ACL was created or modified.

**Historical run status: BLOCKED/INCOMPLETE.** PAM password creation and the
remaining PAM lifecycle behavior were not
fully confirmed by this automated run, and the pre-existing protected `vault-p0-admin@pve` artifact
means a zero-count scan of every `vault-p0-*` user is not an appropriate cleanup
criterion for this environment. The password implementation gate remains
closed.

---

## Probe P0 operator report — password authentication and rotation (29 August 2026)

These results were reported by the operator after the automated 28 August
probe. They are not automated probe output and have not been independently
reproduced. The report identifies the PAM realm and the `POST /access/ticket`
and `PUT /access/password` operations, but does not retain reproducible request
metadata. All passwords, tickets, token secrets, user identifiers, request
bodies, and response bodies remain redacted and were not recorded here.

### Operator-reported result

| Behavior | Result |
|---|---|
| PAM password authentication (`POST /access/ticket`) | HTTP 200; operator-reported and unreproduced |
| PAM password rotation request (`PUT /access/password`) | HTTP 200; operator-reported and unreproduced |
| PAM authentication with the old password after rotation | HTTP 401; operator-reported and unreproduced |
| PAM authentication with the new password after rotation | HTTP 200; operator-reported and unreproduced |
| Rotation verdict | **Operator-reported, not independently confirmed** — the report indicates rotation took effect and invalidated the old password, but it does not independently close the rotation gate. |

This report preserves the operator's evidence but does not close the
password-rotation gate for the engine. The automated PVE results establish
PVE password creation, read-back, authentication, exact renewal, original-
password authentication after renewal, expiry, disablement, deletion, token
interaction, and password length limits. PAM creation failed in the automated
run; PAM authentication and rotation are operator-reported and unreproduced,
while PAM expiry, disablement, deletion, token interaction, ACL requirements,
constraints, and cleanup remain unresolved. The automated probe's pre-existing
`vault-p0-admin@pve` token-owner exception remains in force: that user was not
modified or deleted, and it must not be counted as a disposable probe artifact.

The operator report does not establish behavior for any non-password realm.
By explicit operator decision, non-password realms are outside the current P0
scope and their testing is deferred. Within the password-realm scope, the
PVE evidence is stronger than the PAM evidence; unresolved PAM behavior must
not be inferred from PVE results.

Cleanup verification applies to the disposable users created by the current
probes: the recorded final scans verified those artifacts absent. The
pre-existing `vault-p0-admin@pve` environment-token owner remains protected and
is not a disposable test artifact; it is the preserved cleanup exception. This
does not claim that every `vault-p0-*` user is absent, nor that the protected
owner was cleaned up.

**Historical P0 status:** the broader proposal included PAM and password rotation,
which were not adopted. The supported `pve` password lifecycle is documented by
the later verified-build run below. PAM findings remain historical and non-blocking.

### Deferred follow-up — non-password realms

Testing non-password realms is explicitly deferred by operator decision to a
future operator-approved task.
That task must use a suitable disposable realm and record the same lifecycle,
authentication, token-interaction, ACL, constraint, and cleanup evidence before
any scope decision is made. It is not a current P0 blocker.

---

## Summary — PVE Behavior Contract

This table becomes the **load-bearing contract**. Every PVE behavior the
engine depends on, its confirmation status, and the code area affected.
**Anything UNVERIFIED must not be relied upon in code.**

| # | PVE Behavior | Plan Assumption | Confirmed? | Affected Code | Follow-up |
|---|---|---|---|---|---|
| 0 | Admin token auth + `/version` reachability | 200 + version JSON | Y | `path_config.go` | |
| 1 | `GET /access/permissions` tree shape | Map keyed by ACL path; inner value is propagate flag (0/1) | Y (propagate flag confirmed) | `path_config.go` / `pveapi.PermissionTree` | |
| 1b | `?path=` resolves ancestors server-side | Not currently used | Y (?path= resolves server-side) | `path_config.go` / `pveapi.PermissionTree` | Enables "Lazy Way" — could replace HasPrivilege |
| 2 | Duplicate `userid` on `POST /access/users` | 409 Conflict | N — 500 not 409 | `pveapi/errors.go` + creds retry loop | Map body "already exists" → conflict |
| 3 | `DELETE /access/users/{userid}` for nonexistent user | 404, treated as success | N — 500 not 404 (idempotent via body) | `secret_token.go` revoke | Revoke: match body "no such user" as success |
| 4 | `GET /access/users/{userid}` for nonexistent user | 404 | N — 500 not 404 | `acceptance_test.go` | Acceptance test must not assert 404; use body match |
| 5 | `GET /access/groups/{group}` for nonexistent group | 404 → `ErrNotFound` → friendly message | N — 500 not 404 | `path_roles.go` `GetGroup` | GetGroup: match body "does not exist" |
| 6 | `privsep=0` token inherits user ACL (non-empty perms) | Token perms NON-EMPTY after group assignment | RE-PROBE (Probe 6 flawed) | `pveapi` `CreateToken` | Await Probe 6-fix-E behavioral result |
| 6b | Duplicate `tokenid` on `POST .../token/{tokenid}` | 409 Conflict | N — 400 not 409 | creds token-409 branch | Map 400+"Token already exists" → conflict |
| 7 | `PUT /access/users/{userid}` with `expire` only preserves `groups` | `groups` field unchanged after PUT | N — historical Probe 7 saw `groups:[]`; later live acceptance on build `43df2e01f27a1a19` preserved groups with `append` omitted | `secret_token.go` renew / `acceptance_test.go` control | Omitted-`append` semantics unresolved; renewal must re-send expire+groups+enable+append=1; control uses empty `groups=` with explicit append=0 |
| 8 | Expired user's token returns 401 | 401 once `expire` is in the past | Y — 401 on expired user | creds `expire` backstop | |
| 9 | Permissions tree distinguishes `propagate=0` from `propagate=1` | Config-time check can detect `propagate=0` at `/access/groups` | Y — propagate=0 shows :0 | `path_config.go` validation | C3 fixable: check per-group path /access/groups/<group> at role-write |
| P0-password-create | Password supplied on `POST /access/users` is accepted | Password creation is available through the user-create call | Y for `pve` (automated 28 Aug); historical PAM creation failed with HTTP 500 and no OS account | Password issuance | PAM is out of scope; do not generalize PVE evidence |
| P0-password-auth | Password authenticates through `POST /access/ticket` | Created password can authenticate | Y for `pve` (automated 28 Aug); Y reported for PAM but unreproduced | Future password secret / acceptance tests | PAM result is operator-reported only |
| P0-password-expiry | Past user `expire` rejects password authentication | Expiry is a password backstop | Y for `pve` (automated 28 Aug, HTTP 401) | Future password lifecycle | PAM expiry remains unresolved |
| P0-password-disable | `enable=0` rejects password authentication | Disabled users cannot authenticate | Y for `pve` (automated 28 Aug, HTTP 401) | Future password lifecycle | PAM disablement remains unresolved |
| P0-password-constraints | Password length is bounded | Generator must honor PVE constraints | Y for `pve`: 8–64 accepted; 1–7 and 65 rejected | Future password generator | PAM/charset behavior remains unresolved |
| P0-password-rotation | `PUT /access/password` changes the password | Rotation behavior is available to the engine | API-token call is not exercisable: PVE returned 403 and requires a password-authenticated ticket; PAM 200/old 401/new 200 is operator-reported and unreproduced | Future design decision | Engine auth is API-token-only; exact privilege path and a supported engine rotation mechanism remain unresolved |
| P0-pam-lifecycle | PAM creation and full lifecycle behave like PVE | PAM password behavior matches the `pve` realm | Not evaluated for support; historical creation failed and only authentication/rotation were operator-reported | None | PAM is explicitly out of scope and this row is non-blocking |
| 6-fix | privsep=0 token inheritance (behavioral) | Token can call /cluster/resources?type=vm | SUPERSEDED — see CLEAN | pveapi CreateToken / canary | Confounded; re-run as Probe CLEAN |
| 7-fix | Renewal re-sends expire+groups+enable preserves privileges | groups persist; token works post-renewal | SUPERSEDED — see CLEAN | secret_token.go renew / InternalData | Confounded; re-run as Probe CLEAN |
| CLEAN | Group membership confers role at creation + survives renewal (both oracles) | Synthetic user in group holds PVEVMAdmin; token inherits via privsep=0; survives renewal | Group-add BROKEN via groups= (silent drop) | path_creds.go / secret_token.go / pveapi | Superseded by GROUPADD; 5-A was root@pam confound |
| GROUPADD | Correct group-membership API + read-back assertion | groups= is single-CSV pve-groupid-list, user-side only, silently drops unresolvable w/ HTTP 200; verify via read-back | Y — CONFIRMED (single-call works; read-back via users.groups or groups.members) | pveapi CreateUser + GetUser; creds read-back; renewal re-send | Renewal re-sends expire+groups+enable+append=1; store group in InternalData; read-back assert on issue |
| RENEWAL-PRESERVE | Renewal PUT re-sending groups preserves membership | `groups` field unchanged (present) after PUT expire+groups+enable+append=1 on a confirmed-member user | Y — CONFIRMED (renewal re-sending groups preserves membership; Probe RENEWAL-PRESERVE) | secret_token.go renew / read-back assert | Wording promoted to confirmed across AGENTS/README/ARCHITECTURE |
| COMMENT | `comment` round-trips byte-for-byte through POST/GET (P2) AND the engine's renewal PUT (append=1, comment omitted) leaves comment intact (P1) | (a) GET returns comment byte-for-byte; (b) renewal PUT (expire+groups+enable+append=1, comment omitted) does NOT clear comment | Y — BOTH CONFIRMED on PVE 9.2.10 (Probe COMMENT, 19 Aug 2026). Renewal PUT (append=1, comment omitted) preserves comment — CONFIRMED; general full-replace semantics for comment NOT tested (no append=0 run) and not relied upon. The `vault-wal:` marker is durable for the full account lifetime under the engine's actual call shape. | pveapi walRollbackUser (ownership check); operator note in ARCHITECTURE.md | Validates WAL nonce-ownership scheme end-to-end. No code change needed. UpdateUser correctly omits comment and always sends append=1. |

## Spike Conclusion

The Phase 0 spike is COMPLETE. The core credential mechanism is CONFIRMED viable
on PVE 9.2.10.

Summary of load-bearing findings that MUST shape the implementation:

1. **Error contract:** PVE returns HTTP 500 with a message body for conditions REST APIs would
   code 404/409 (duplicate user → 500 "already exists"; missing user/group GET/DELETE → 500
   "no such user"/"does not exist"). Duplicate tokenid → 400 "Token already exists". The engine
   MUST map on BODY STRING, not status code. Revocation/GetGroup idempotency keys on body text.

2. **Group membership WORKS via single-call create:** `POST /access/users` with `groups=<CSV>`
   lands membership. Verifiable via `GET /access/users/{id}`.groups OR `GET /access/groups/{id}`.members.
   privsep=0 token inherits the group-derived role (full PVEVMAdmin confirmed via node oracle).

3. **Encoding:** `groups` is a `pve-groupid-list` — send as ONE comma-separated field, never
   array-repeated. Every group write should be read-back-asserted (PVE silently drops
   unresolvable group ids with HTTP 200 on the modify/append path). **Incidental finding
   (Probe RENEWAL-PRESERVE):** on the CREATE path (`POST /access/users`), a nonexistent group
   causes PVE to REJECT with HTTP 500 "no such group" rather than silently drop. The
   silent-drop-with-200 behavior appears specific to the modify/append path. The read-back
   assertion is correct defensive practice regardless.

4. **Renewal:** Historical Probe 7 showed replacement-style `PUT /access/users/{id}` can wipe
   groups, while later live acceptance on build `43df2e01f27a1a19` preserved groups when
   `append` was omitted; omitted-`append` semantics are unresolved and must not be relied upon.
   **Probe RENEWAL-PRESERVE (17 Aug 2026) confirms the engine path:** a PUT re-sending
   `expire`+`groups`+`enable`+`append=1` PRESERVES group membership (expire advanced from
   1786986804 → 1786990429; groups field intact). Renewal MUST re-send these fields together.
   Store the target group in lease InternalData (renewal must not depend on the role still
   existing). **Probe COMMENT (19 Aug 2026):** the engine's renewal PUT (expire+groups+enable+append=1,
   comment omitted) leaves `comment` intact — the `vault-wal:` nonce marker survives the whole account
   lifetime under the engine's actual call shape. `UpdateUser` correctly omits `comment` and always
   sends `append=1`; no code change needed. **Scope note:** COMMENT-3 used `append=1`; this run does
   NOT establish general full-replace semantics for `comment` (a PUT without `append=1` was not tested).
   The engine only sends `append=1` on renewal, so the scoped result is sufficient.

5. **Permissions tree:** `GET /access/permissions` returns a propagate-flag map; `?path=` and
   `?userid=` resolve server-side. Config-time validation reads the admin token's OWN perms
   (no extra grant needed). Bare `/access/permissions` for a token reflects only that principal.

6. **C3 (propagate-0 detection):** propagate flag IS visible (:0 vs :1), so misconfig is
   detectable — BUT for a grant AT the exact path `/access/groups`, add a per-group-path check
   (`/access/groups/<group>`) at role-write to catch propagate=0.

7. **Expire backstop:** an expired user's token returns 401 — the defense-in-depth backstop works.

See the per-probe tables above for evidence. These findings supersede the corresponding
"confirmed on PVE 9.2.10" annotations in ARCHITECTURE.md where they conflict.

## Probe P0 verification run — implemented password mode on PVE 9.2.14 (29 August 2026)

**Target build: `pve-manager/9.2.14/a1480fa6b8d899cb` (running kernel
6.17.13-3-pve).** This is a DIFFERENT build from the `9.2.10/43df2e01f27a1a19`
target used by every probe above; the results below are attributed to 9.2.14 and
do not restate 9.2.10 evidence.

Provenance: automated, reproducible run of the engine's own acceptance suite
against a disposable target, plus an operator manual pass through a real
`vault server` (`-dev-plugin-dir`). No password, token secret, or ticket value
was printed — the password test asserts HTTP status codes only.

Commands:

```text
make testacc
go test -count=1 -v -timeout=30m ./... -run '^TestAccPasswordLifecycle$'
```

**Open evidence gap — `GET /version` body on 9.2.14.** The engine now gates
password mode on the `version` and `repoid` fields of `GET /version` matching
`9.2.14` / `a1480fa6b8d899cb`. The expected `repoid` is taken from the
`pve-manager` build string, not from a recorded API response on this build: the
only `/version` body recorded here is Probe 0's on 9.2.10 (see that probe's
Body string row), where `repoid` does equal the build-string suffix. Capture and record the raw
9.2.14 `/version` body on the next live run to close this gap; if the two ever
disagree, the gate rejects the one verified build.

| Behavior (realm `pve`) | Result on 9.2.14 |
|---|---|
| Password supplied on `POST /access/users` (single call) | Accepted; user read-back HTTP 200 with expected group and comment marker |
| Password authentication via `POST /access/ticket` | HTTP 200 |
| API token minted in password mode | None — the user's token list is empty (`CreateToken` is never called) |
| Exact engine renewal (`expire`+`groups`+`enable`+`append=1`) | HTTP 200; group membership read back intact |
| ORIGINAL password after that renewal | HTTP 200 — renewal does not invalidate the password |
| Expiry backstop (`expire` in the past) | Password authentication HTTP 401 |
| Restored future `expire` | Password authentication HTTP 200 again |
| Disablement (`enable=0`) | Password authentication HTTP 401 |
| Revocation (`DELETE /access/users/{userid}`) | User absent afterwards; password authentication HTTP 401 |
| Password rotation | NOT exercised — not implemented, and unreachable with API-token authentication |
| PAM realm | NOT exercised — refused at role-write time by design |

The same run also re-confirmed token-mode behavior on 9.2.14: `TestAccLifecycle`,
the required positive authorization canary, revocation idempotency after an
out-of-band delete, WAL rollback, concurrent issuance, and the delete-config
guard all passed. The three optional canaries (direct ACL
anti-privilege-escalation, negative authorization, insufficient privileges)
SKIPPED because their documented prerequisites were unset; skips are not
completed tests.

## Password-credential P0 status — STILL PARTIAL/OPEN (broader proposal)

The 9.2.14 verification run closes the supported `pve`-realm behavior the engine
depends on. The broader historical P0 proposal remains partial/open because PAM
and password rotation are not supported. PAM is explicitly out of scope, and the historical PAM results above
are non-blocking. Password rotation is unsupported because `PUT /access/password`
cannot be exercised with the engine's API-token-only authentication.

Password mode is implemented by explicit operator decision and restricted to
exactly the confirmed surface: `pve` realm only on
`pve-manager/9.2.14/a1480fa6b8d899cb`, with no rotation.

## Scope decision — 29 August 2026

The operator decision is to support password credentials only for the `pve`
realm on the verified 9.2.14 build. PAM is explicitly out of scope; its
historical creation, authentication, and rotation observations remain evidence
only and must not be generalized into supported behavior. Password rotation is
also out of scope for this API-token-authenticated engine.

This dated scope decision does not rewrite the historical run statuses above:
`BLOCKED/FAILED`, `BLOCKED/INCOMPLETE`, and other recorded outcomes remain as
reported. The narrower supported `pve` surface is a later decision, not evidence
that the broader PAM or password-rotation proposal was completed.
