# Implementation Plan — Vault Secrets Engine for Proxmox VE

## Overview

This is a greenfield Go implementation of the Proxmox VE dynamic-secrets engine specified in `docs/ARCHITECTURE.md`. The plugin issues throwaway Proxmox API tokens by creating synthetic per-lease PVE users, adding them to operator-pre-created PVE groups (which cluster admins have already bound to desired ACL roles), and minting API tokens on those users. Revocation deletes the user, which cascades to remove tokens, group memberships, and ACL entries in one call. The plugin targets Proxmox VE 9.2.10 and is built on `hashicorp/vault/sdk`.

## Locked Decisions

These design choices are baked into the implementation and are **not open for revision** during initial implementation:

- **Go version**: `go 1.25.7` (bumped to satisfy `vault/sdk v0.25.1`'s minimum; was 1.23 in the original plan). CI must use Go **≥ 1.25.7**.
- **Go module path**: `github.com/hazmei/vault-plugin-secrets-proxmox`
- **DELETE `<mount>/config` guard**: ALWAYS requires `force=true` query parameter. The engine does NOT track active leases (no reliable SDK lease-count API; a counter would drift on crash/failover). Outstanding leases become non-revocable and non-renewable on config delete — renewal also loads config to reach PVE, so it fails immediately too; operators must revoke leases first, then delete config.
- **userid-collision retry bound**: 5 attempts maximum, then surface as internal error.
- **Random suffix format**: 8-character lowercase base32 (Crockford-style alphabet without padding), generated from `crypto/rand` (~40 bits entropy).
- **WAL kind name**: `"user"`; `WALRollbackMinAge`: 5 minutes. WAL payload keys are `user_id` and `nonce`.
- **WAL nonce contract**: Every issuance attempt generates `nonce = "vault-wal:" + <8-character random suffix>`. The exact nonce string is stored in the WAL payload and written to the PVE user's `comment`; rollback deletes only when the live comment equals the WAL nonce. This WAL ownership check is distinct from revoke idempotency, which keys on the PVE body string `"no such user"`.
- **Token `tokenid`**: Fixed as `lease` (every issued token has `tokenid=lease`; uniqueness comes from the per-lease unique userid).
- **No active_lease_count counter**: The engine does NOT track a counter of active leases anywhere in storage (neither in config nor separate keys). Lease tracking is left to Vault core.
- **TTL computation uses `framework.CalculateTTL`** (`vault/sdk/framework/lease.go`), not a hand-rolled `min()` helper. It already implements role-value → config-default → `sysView.DefaultLeaseTTL()` fallback, caps at `min(backendMaxTTL, sysView.MaxLeaseTTL())`, and caps renewals from `startTime` (the lease `IssueTime`). There is no `ttl.go`.
- **No issuance-time requested TTL**: `<mount>/creds/:role` declares NO `ttl` field, matching the database and terraform secrets engines. The effective TTL comes from role values with config defaults as fallback; `increment` is passed to `CalculateTTL` only on renewal (from `req.Secret.Increment`).
- **`expire=0` (unlimited TTL) policy**: The engine REFUSES issuance when the effective TTL resolves to 0 (unlimited). Sending PVE `expire=0` creates a never-expiring user, disabling the `expire` backstop — the sole defense-in-depth if Vault revocation is delayed or fails. `creds/:role` returns a clear error: `"role %q resolves to an unlimited TTL; set a non-zero ttl/max_ttl on the role or config default_ttl/default_max_ttl (the PVE expire backstop requires a finite lease)"`. (Alternative considered and rejected as more complex: floor the PVE `expire` at `now + effMaxTTL + grace` when a finite max exists but ttl is 0.) This makes the backstop non-optional.

## Confirmed Password Credential Decisions

The following contract is confirmed for the future password credential feature. It is
tracking-only until the live PVE probe in P0 passes; these decisions do not authorize
password implementation in the current token-only release.

- The role field is `mode` with values `token` and `password`.
- An omitted `mode` defaults to `token`, preserving existing role and lease behavior.
  `getRole()` MUST normalize a decoded empty `mode` to `token` before returning the
  role. Legacy stored-role tests are required; write-time defaulting alone is not
  sufficient.
- A password response contains exactly `user_id` and `password`.
- Password mode creates no PVE API token and uses a separate Vault secret type.
- The password is never stored in WAL or `Secret.InternalData`, and is never written to logs.
- Existing token roles and leases remain compatible and are not migrated.

### Probe-dependent password design intent

Password renewal is intended to extend the PVE user expiry only, without rotating or
returning the password. This is not a confirmed PVE behavior yet. It remains
conditional on P0 evidence for the exact engine renewal shape and a successful
authentication attempt with the original password after renewal.

## Repository Layout

```
vault-plugin-secrets-proxmox/
├── cmd/
│   └── vault-plugin-secrets-proxmox/
│       └── main.go              # plugin entry: BackendFactory + plugin.Serve
├── internal/
│   └── pveapi/                  # package pveapi — NOT "proxmox" (the root package is
│       │                        # package proxmox; two packages named proxmox in one
│       │                        # build is legal but confusing)
│       ├── client.go            # real PVE API client (Client interface + impl)
│       ├── types.go             # request/response structs, PermissionTree
│       ├── errors.go            # typed errors (NotFound/Conflict/Forbidden)
│       ├── mock.go              # mock client for unit tests
│       └── permission_tree_test.go  # lives here — PermissionTree is in this package
├── backend.go                   # framework.Backend factory, path list, Secret + WAL registration, client cache/invalidate
├── path_config.go               # config POST/GET/DELETE
├── path_roles.go                # roles POST/GET/LIST/DELETE
├── path_creds.go                # creds GET (mutating ReadOperation)
├── secret_token.go              # Secret schema + Revoke/Renew callbacks
├── wal.go                       # WAL entry struct + walRollback
├── userid.go                    # userid assembly, charset + length validation, suffix gen
├── *_test.go                    # unit tests (mock client)
├── acceptance_test.go           # TestAcc* (VAULT_ACC gated)
├── go.mod / go.sum
├── .gitignore
├── Makefile
├── .golangci.yml
├── scripts/
│   └── verify-plugin-artifact.sh # operator-run artifact/permission verification
├── docs/
│   ├── ARCHITECTURE.md
│   ├── IMPLEMENTATION_PLAN.md
│   ├── PRODUCTION_VERIFICATION.md
│   └── PVE_PROBES.md
├── README.md
├── AGENTS.md
└── LICENSE
```

## Bootstrap Files

### `go.mod`

```go
module github.com/hazmei/vault-plugin-secrets-proxmox

go 1.25.7  // resolved: bumped from 1.23 to satisfy vault/sdk v0.25.1 minimum

require (
	github.com/hashicorp/vault/sdk v0.25.1
	github.com/hashicorp/go-hclog v1.6.3
)
```

The versions above reflect what `go get` resolved at bootstrap time (sdk v0.25.1, go-hclog v1.6.3, go directive 1.25.7). Run `go mod tidy` after any `go get` to keep go.sum consistent.

### `.gitignore`

Standard Go ignores plus Vault plugin artifacts:

```
# Binaries
/bin/
/dist/
/vault/plugins/
*.test
*.exe
*.dll
*.so
*.dylib

# Go build
vendor/
*.out

# Environment
.env
.env.*

# IDE
.vscode/
.idea/
*.swp
*.swo
*~

# OS
.DS_Store
Thumbs.db
```

Add a Go `.gitignore` **before** creating any build artifacts.

### `Makefile`

```makefile
PLUGIN_NAME := vault-plugin-secrets-proxmox
PLUGIN_DIR := vault/plugins
GO_FILES := $(shell find . -name '*.go' -not -path './vendor/*')

.PHONY: build
build:
	@mkdir -p $(PLUGIN_DIR)
	go build -o $(PLUGIN_DIR)/$(PLUGIN_NAME) ./cmd/vault-plugin-secrets-proxmox

.PHONY: test
test:
	go test -v ./...

.PHONY: testacc
testacc:
	@missing=""; \
	[ -n "$$PVE_ADDR" ] || missing="$$missing PVE_ADDR"; \
	[ -n "$$PVE_TOKEN_ID" ] || missing="$$missing PVE_TOKEN_ID"; \
	[ -n "$$PVE_TOKEN_SECRET" ] || missing="$$missing PVE_TOKEN_SECRET"; \
	[ -n "$$PVE_TEST_GROUP" ] || missing="$$missing PVE_TEST_GROUP"; \
	[ -n "$$PVE_BEHAVIORAL_PATH" ] && [ "$$PVE_BEHAVIORAL_PATH" != "/version" ] || missing="$$missing PVE_BEHAVIORAL_PATH"; \
	[ -n "$$PVE_BEHAVIORAL_MARKER" ] || missing="$$missing PVE_BEHAVIORAL_MARKER"; \
	if [ -n "$$missing" ]; then \
		echo "missing or invalid required acceptance environment variables:$$missing" >&2; \
		echo "set these before running make testacc; optional variables are not required" >&2; \
		exit 1; \
	fi
	VAULT_ACC=1 go test -count=1 -v -timeout=30m ./... -run TestAcc

.PHONY: fmt
fmt:
	gofmt -s -w $(GO_FILES)

.PHONY: lint
lint:
	golangci-lint run

.PHONY: tidy
tidy:
	go mod tidy

.PHONY: clean
clean:
	rm -rf $(PLUGIN_DIR) bin/ dist/
```

Targets: `build` → compile to `vault/plugins/`; `test` → unit tests; `testacc` → operator-run live acceptance tests with required env preflight (`PVE_BEHAVIORAL_PATH` must be set to a group-role-gated endpoint, not `/version`) and a 30-minute Go test timeout (`VAULT_ACC=1`, verbose, non-cached `TestAcc` run); `fmt` → `gofmt`; `lint` → `golangci-lint run`; `tidy` → `go mod tidy`.

### `.golangci.yml`

Minimal linter config:

golangci-lint **v2** schema (v2 dropped `govet.check-shadowing` in favour of
`govet.enable: [shadow]`, and moved `gofmt` from `linters` to `formatters`; a v1-style
config errors out on v2):

```yaml
version: 2

linters:
  enable:
    - govet
    - staticcheck
    - errcheck
    - ineffassign
  settings:
    govet:
      enable:
        - shadow
    errcheck:
      check-blank: true

formatters:
  enable:
    - gofmt

run:
  timeout: 5m
```

If CI pins golangci-lint v1 instead, use the v1 schema (`linters-settings:`,
`govet.check-shadowing: true`, `gofmt` under `linters`) and pin the version explicitly in the
CI workflow — do not mix the two.

## Package & File Responsibilities

### `cmd/vault-plugin-secrets-proxmox/main.go`

Plugin entry point. Calls `plugin.ServeMultiplex` (multiplexed gRPC, recommended for Vault v1.12+; **do NOT set `TLSProviderFunc`** — Vault v5+ AutoMTLS handles TLS without it) with `BackendFactoryFunc: proxmox.Factory`.

**Key functions**:
- `main()` — sets up logging, calls plugin serve.

### `backend.go`

Backend factory and root struct.

**Key types**:
```go
type backend struct {
    *framework.Backend
    client   pveapi.Client  // cached PVE API client
    clientMu sync.RWMutex   // guards client cache
}
```

**Key functions**:
- `Factory(ctx, *logical.BackendConfig) (logical.Backend, error)` — public factory function called by plugin serve.
- `newBackend(ctx, *logical.BackendConfig) (*backend, error)` — constructs the backend struct, sets:
  - `Help` — help text
  - `BackendType: logical.TypeLogical`
  - `PathsSpecial: &logical.Paths{SealWrapStorage: []string{"config"}}` — seal-wrap `token_secret`
  - `Paths: []*framework.Path{pathConfig(b), pathRoles(b), pathCreds(b)}`
  - `Secrets: []*framework.Secret{secretToken(b)}`
  - `WALRollback: b.walRollback`
  - `WALRollbackMinAge: 5 * time.Minute`
  - `InvalidateFunc: b.invalidate` — clears cached client on config change
- `getClient(ctx, storage) (pveapi.Client, error)` — lazy-builds and caches the PVE API client from stored config; called by path handlers.
- `invalidate(ctx, key)` — clears `b.client` cache when the `config` key changes.

**References**: `docs/ARCHITECTURE.md` — Storage Schema, Configuration, HTTP Client and Connection Pooling sections.

### `path_config.go`

Config path: `<mount>/config` (POST/GET/DELETE).

**Key types**:
```go
type proxmoxConfig struct {
    Address        string `json:"address"`
    TokenID        string `json:"token_id"`
    TokenSecret    string `json:"token_secret"` // never returned on GET
    TLSSkipVerify  bool   `json:"tls_skip_verify"`
    CACert         string `json:"ca_cert"`
    DefaultTTL     int    `json:"default_ttl"`
    DefaultMaxTTL  int    `json:"default_max_ttl"`
}
```

**Key functions**:
- `pathConfig(b) *framework.Path` — path definition (POST/GET/DELETE operations).
- **Write handler**:
  1. Validate `default_ttl <= default_max_ttl` (when both set).
  2. Build a `pveapi.Client` with provided credentials.
  3. Call `client.GetVersion()` (reachability/TLS check).
  4. Call `client.GetPermissions()` — returns `PermissionTree`.
  5. Parse tree, walk ancestor paths, confirm `User.Modify` and `Sys.Audit` at `/access/groups` (see ancestor-walk note below).
  6. Store config to storage key `config` (encrypted/seal-wrapped). Use this exact literal everywhere — it must match `PathsSpecial.SealWrapStorage: []string{"config"}` and the `invalidate(ctx, key)` comparison.
  7. Invalidate cached client in backend (triggers rebuild on next use).
  8. **Overwrite warning**: if a config already existed and `address` or `token_id`/`token_secret` changed, add a response warning: `"config address/token changed; outstanding leases were issued against the previous admin token and may become non-revocable if the old token can no longer delete their users — revoke outstanding leases before changing connection credentials"`. (The engine does not track leases, so this is advisory, not a hard block — parallels the DELETE force=true guard's rationale.)
- **Read handler**: Return all fields EXCEPT `token_secret`. Include `token_id` (identity, not credential).
- **Delete handler**: Require `force=true`. If missing, return error `"DELETE <mount>/config requires force=true"`. If present, delete the `config` entry and invalidate cached client. Declare `force` as a `framework.TypeBool` field on the path and read it with `d.Get("force")`; it arrives as a query parameter (`vault delete proxmox/config force=true` requires Vault CLI ≥ 1.11, which sends K=V pairs on DELETE as query params — otherwise `curl -X DELETE ".../config?force=true"`). Confirm in the smoke test.

**Ancestor-path walk validation** (see `docs/ARCHITECTURE.md` Configuration section, Implementation note on permission-tree ancestor walk): `GetPermissions()` returns a `PermissionTree` (map keyed by ACL paths that have explicit entries). A propagating grant at `/access` will NOT appear as a literal key at `/access/groups`. Therefore, to check if `User.Modify` is held at `/access/groups`, test: exact path `/access/groups` OR any ancestor (`/access`, `/`) where the privilege is propagating. Implement a helper `PermissionTree.HasPrivilege(path, priv string) bool` that walks up the path (`/access/groups` → `/access` → `/`) and checks each.

**Mock seam for config-write validation** (unit-test injection point): The write handler builds a `pveapi.Client` from INCOMING credentials BEFORE storing config, so unit tests cannot use a pre-seeded `b.client` cache (the cache is populated after storage; validation happens first). To make `path_config_test.go` injectable, expose a `newClient func(cfg *proxmoxConfig) (pveapi.Client, error)` field on the backend struct, defaulting to the real constructor. The config-write handler calls `b.newClient(cfg)` instead of the constructor directly; tests replace `b.newClient` with a factory that returns a mock.

**References**: `docs/ARCHITECTURE.md` — Configuration section, Required privilege scoping, DELETE config behavior, ancestor-path walk (Implementation note on permission-tree ancestor walk).

### `path_roles.go`

Roles path: `<mount>/roles/:name` (POST/GET/LIST/DELETE).

**Key types**:
```go
type proxmoxRole struct {
    Group      string `json:"group"`
    UserPrefix string `json:"user_prefix"`
    Realm      string `json:"realm"`
    TTL        int    `json:"ttl"`
    MaxTTL     int    `json:"max_ttl"`
}
```

**Key functions**:
- `pathRoles(b) *framework.Path` — path definition (POST/GET/LIST/DELETE operations).
- **Write handler**:
  1. Validate `ttl <= max_ttl` (when both set).
  2. **Default `realm` to `"pve"` when empty** (per `docs/ARCHITECTURE.md` realm default, ~line 223). Then **validate `realm` charset against the PVE realm regex `^[A-Za-z][A-Za-z0-9.\-_]+$`** (must start with a letter). Reject with a clear error BEFORE the length-budget check (an invalid realm otherwise produces a confusing length error or an issue-time 400).
  3. Validate `user_prefix` and role `:name` charset (see `userid.go`).
  4. Validate userid length budget: `len(user_prefix) + 1 + len(role) + 1 + 8 (random suffix) + 1 + len(realm) <= 64` (see `docs/ARCHITECTURE.md` Roles section — synthetic userid format and length budget). This runs AFTER realm defaulting so the budget uses the effective realm.
  5. Load config, build client (via `getClient`).
  6. Call `client.GetGroup(role.Group)` — confirm group exists (GetGroup returns ErrGroupNotFound when PVE responds HTTP 500 + body "does not exist" — NOT 404). Surface ErrGroupNotFound as `"group <name> does not exist on Proxmox cluster"`.
  7. Call `client.GetPermissions()`, parse tree, confirm `Realm.AllocateUser` at `/access/realm/<role.realm>` via ancestor-path walk.
   7b. Per-group-path check (propagate-0 detection, see PVE_PROBES.md Probe 9): confirm User.Modify is EFFECTIVE at the exact
      per-group path /access/groups/<role.Group> using HasPrivilege. This catches a --propagate 0
      grant at /access/groups (the propagate flag IS visible :0 vs :1, Probe 9; creation checks the
      PER-GROUP path while a propagate=0 parent grant does not propagate down). If not effective,
      reject with "admin token lacks User.Modify at /access/groups/<group> (check --propagate 1)".
  8. Store role to `roles/<name>`.
- **Read handler**: Load and return role from `roles/<name>`.
- **List handler**: List keys under `roles/`.
- **Delete handler**: Delete `roles/<name>`. Does NOT revoke outstanding leases (see `docs/ARCHITECTURE.md` Roles section, "Deleting a role does not revoke its outstanding leases").

**References**: `docs/ARCHITECTURE.md` — Roles section, role-write validation, userid character set and length budget.

### `path_creds.go`

Creds path: `<mount>/creds/:role` (GET — mutating ReadOperation).

**Key functions**:
- `pathCreds(b) *framework.Path` — path definition (ReadOperation).
- `handleCredsRead(ctx, req, data) (*logical.Response, error)` — full credential issuance (see Credential Lifecycle below).

**References**: `docs/ARCHITECTURE.md` — Credentials section, Implementation Notes — Service API Calls and Issuance ordering detail, WAL-Based Orphan Recovery section.

### `secret_token.go`

Secret type definition and lifecycle callbacks.

**Key functions**:
- `secretToken(b) *framework.Secret` — defines the `pve_token` secret type:
  - `Type: "pve_token"`
  - `Fields: schema for user_id, token_id, token_secret` (data returned to user)
  - `Renew: b.secretTokenRenew`
  - `Revoke: b.secretTokenRevoke`
  InternalData additionally carries `group` (not a user-facing Field) — the Renew callback reads it to re-send `groups=` on the full-replace PUT. Ensure the issuance path writes `group` into InternalData.
- `secretTokenRenew(ctx, req, data) (*logical.Response, error)` — renewal callback (see Renewal below).
- `secretTokenRevoke(ctx, req, data) (*logical.Response, error)` — revocation callback (see Revocation below).

**References**: `docs/ARCHITECTURE.md` — Credentials section response schema, Lease Renewal section, Revocation section.

### `internal/pveapi/client.go`

PVE API client interface and real implementation.

**Client interface**:
```go
type Client interface {
    GetVersion(ctx) (string, error)
    GetPermissions(ctx) (PermissionTree, error)
    GetGroup(ctx, group string) error  // ErrGroupNotFound mapped from 500 + body "does not exist"
    CreateUser(ctx, req CreateUserRequest) error  // ErrConflict from 500 + body "already exists"
    GetUser(ctx, userid string) (UserInfo, error)  // NEW: read-back; ErrUserNotFound from 500 + body "no such user"
    CreateToken(ctx, userid, tokenid string) (string, error)  // always sends privsep=0; returns token secret; ErrConflict from 400 + body "Token already exists"
    UpdateUser(ctx, req UpdateUserRequest) error  // RENAMED; full-replace, re-sends groups
    DeleteUser(ctx, userid string) error  // ErrUserNotFound from 500 + body "no such user" (idempotent)
}

type CreateUserRequest struct {
    UserID string
    Groups string  // pve-groupid-list: ONE comma-separated field, NEVER array-repeated
    Expire int64
    Enable bool
    Comment string // WAL ownership nonce: vault-wal:<8-char-random>
}

// NEW: renewal must re-send expire+groups+enable+append because PUT is full-replace.
type UpdateUserRequest struct {
    UserID string
    Expire int64
    Groups string  // MUST be re-sent on renewal or membership is wiped (Probe 7 / GROUPADD)
    Enable bool    // send enable=1
    Append bool    // send append=1
}

// NEW: read-back shape for GetUser (assert Groups after create/renew).
type UserInfo struct {
    Groups []string
    Enable bool
    Expire int64
    Comment string
}
```

**Real client implementation**:
- HTTP client configured with `tls_skip_verify` or `ca_cert`.
- Auth header: `Authorization: PVEAPIToken=<token_id>=<token_secret>` (where `token_id` is already in `<user>@<realm>!<tokenid>` format from config).
- Base URL: append `/api2/json` to the configured address as given (do not prepend a scheme; the configured `address` already includes the scheme, e.g. `https://pve.example.com:8006`).
- **Error mapping is BODY-STRING based for PVE business errors, with HTTP 401/403 handled as genuine statuses before body-string classification** (confirmed PVE 9.2.10, PVE_PROBES.md Probes 2–6b). PVE returns HTTP 500 (and 400 for token conflict) with an error body for conditions REST would code 404/409. **The match must run against the complete bounded body, not just the `message` field**: the duplicate-tokenid string `"Token already exists"` lives in `errors.tokenid`, NOT in `message` (Probe 6b: `{"message":"Parameter verification failed.\n","data":null,"errors":{"tokenid":"Token already exists."}}`). The client first reads the body with N+1 truncation detection (`maxResponseBodyBytes+1`) and returns `ErrResponseTooLarge` before JSON parsing or business-error classification if the cap is exceeded. Only complete bounded bodies reach `classifyPVEError(status int, body []byte) error`, which checks HTTP 401/403 before body-string matching, then searches the decoded body — the top-level `message` string AND every value under the `errors` object — for the following substrings (case-insensitive, tolerant of trailing `\n` and embedded quoted ids). Implementation: decode into `struct{ Message string; Errors map[string]string }`, then concatenate `Message` + all `Errors` values into one haystack, falling back to raw-body matching only for malformed/plain-text responses or empty structured fields, and match:
  - HTTP 401 (any body, including empty) → `ErrUnauthenticated` (genuine status; check before body-string classification)
  - HTTP 403 (any) → `ErrForbidden` (403 IS a real status)
  - body contains `"already exists"` (user create, HTTP 500) → `ErrConflict`
  - body contains `"Token already exists"` (token create, HTTP 400) → `ErrConflict`
  - body contains `"no such user"` (GET/DELETE user, HTTP 500) → `ErrUserNotFound`
  - body contains `"does not exist"` (GET group, HTTP 500) → `ErrGroupNotFound`
  - body contains `"no such group"` (create user with nonexistent group, HTTP 500) → `ErrGroupNotFound`
  - everything else → wrapped error carrying status + endpoint (redact body for token endpoints).
  Do NOT branch on 404/409 — PVE never returns them for these conditions. Oversized responses deliberately fail closed as `ErrResponseTooLarge`: for example, an oversized HTTP 500 DELETE response that contains `"no such user"` must not become `ErrUserNotFound`/idempotent revocation success unless the full body fits inside the cap. Vault core already retries revoke/renew on any returned error, so no separate retryable type is needed (see `errors.go`).

**Form-encoding rules (both are silent-failure traps)**:
- `privsep` MUST be serialized as the literal `0` on `POST /access/users/{userid}/token/{tokenid}` — never omitted. A Go `bool` written with a "skip zero value" encoder drops the field, and PVE then defaults to `privsep=1`, yielding a token with an empty ACL and zero effective permissions. Build the form with explicit `url.Values{"privsep": {"0"}}`-style writes, not struct-tag omitempty encoding.
- `enable` likewise serializes as the literal `1` on `POST /access/users`.
- `groups` MUST be serialized as ONE comma-separated field (`groups=a,b,c`), NEVER as repeated keys. PVE's `pve-groupid-list` parser mishandles array-repeated keys. For the single-group case send `groups=<role.Group>` verbatim.
- `append` MUST be serialized as the literal `1` on renewal PUTs (`UpdateUser`). Omitted-`append` semantics are unresolved across observed PVE 9.2.10 runs; do not rely on the server default.

**Secret hygiene**: `token_secret` (the admin one from config, and the issued one in the `POST .../token/...` response body) must never appear in an error string or log line. When wrapping a non-2xx response, include status and endpoint; include the body only for non-token endpoints, or redact it.

**References**: `docs/ARCHITECTURE.md` — Service API Summary, Configuration (token auth header), Implementation Notes — Service API Calls and Delete operation, Proxmox Cluster Considerations section.

### `internal/pveapi/types.go`

Request/response structs and permission tree.

**Key types**:
```go
// path → privilege → propagate flag (1 = propagates to child paths, 0 = this path only).
// The int is NOT a bitmask and NOT mere presence.
type PermissionTree map[string]map[string]int

// HasPrivilege reports whether priv is effective at path.
//   - exact-path entry  → satisfied regardless of the propagate flag
//   - ancestor entry    → satisfied ONLY if the propagate flag is non-zero
// Walks path → parent → ... → "/".
func (t PermissionTree) HasPrivilege(path, priv string) bool
```

The exact/ancestor distinction is what makes the `--propagate 0` misconfiguration described
in `AGENTS.md` detectable at config-write time instead of at first issuance. **Confirmed on
PVE 9.2.10 (PVE_PROBES.md Probe 1):** `GET /access/permissions` returns the propagate flag
as the inner value (1 = propagating, 0 = non-propagating). The `HasPrivilege` ancestor-walk
design correctly distinguishes the two cases; no plan revision needed.

**References**: `docs/ARCHITECTURE.md` — Configuration section, Implementation note on permission-tree ancestor walk.

### `internal/pveapi/errors.go`

Typed errors for mapping PVE HTTP responses.

**Key errors**:
```go
// Business errors are mapped by BODY STRING (PVE 9.2.10 returns 500/400 with a message body
// for these conditions); HTTP 401/403 are genuine status codes checked before body matching.
var ErrUserNotFound  = errors.New("pveapi: user not found")  // body "no such user" (HTTP 500)
var ErrGroupNotFound = errors.New("pveapi: group not found") // body "does not exist" / "no such group" (HTTP 500)
var ErrConflict      = errors.New("pveapi: conflict")        // body "already exists" (HTTP 500) / "Token already exists" (HTTP 400)
var ErrUnauthenticated = errors.New("pveapi: unauthenticated") // HTTP 401 (genuine status; expired/revoked/invalid token)
var ErrForbidden     = errors.New("pveapi: forbidden")       // HTTP 403 (genuine status)
var ErrResponseTooLarge = errors.New("pveapi: response body too large") // response exceeds 1 MiB cap before parsing/classification
```

No `RetryableError` type: nothing consumes it. Issuance errors go straight back to the
caller; renew and revoke errors are returned to Vault core, whose built-in retry/backoff
handles quorum loss and cluster-lock contention (`docs/ARCHITECTURE.md` Proxmox Cluster Considerations section). Add
the type only if a call site actually branches on it.

**References**: `docs/ARCHITECTURE.md` — Error Handling section, Proxmox Cluster Considerations section.

### `internal/pveapi/mock.go`

In-memory mock implementing `Client` interface for unit tests. Programmable behavior (inject errors, track calls, pre-seed group/user state).

### `wal.go`

WAL entry and rollback logic.

**Key types**:
```go
const walTypeUser = "user"

const walCommentPrefix = "vault-wal:"

type walUser struct {
    UserID string `json:"user_id" mapstructure:"user_id"`
    Nonce  string `json:"nonce" mapstructure:"nonce"`
}
```

**Key functions**:
- `walRollback(ctx, req, kind, data) error` — registered via `backend.WALRollback` (type `framework.WALRollbackFunc`):
  1. Reject unknown `kind`.
  2. Decode `data` into `walUser`. **`data` arrives as `interface{}` holding a `map[string]interface{}`** (the WAL entry is JSON round-tripped through storage), NOT a `walUser` — decode with `mapstructure.Decode` or a `json.Marshal`/`Unmarshal` round-trip. A direct type assertion to `walUser` panics/fails. Required payload keys are `user_id` and `nonce`; do not add compatibility aliases.
     - If `user_id` is missing or empty: return an error (WAL entry retained; rollback retries/alerts). The engine cannot safely infer the cleanup target.
  3. Load config, build client.
  4. Call `client.GetUser(userid)`.
     - If ErrUserNotFound (body "no such user", HTTP 500): return nil (WAL entry deleted; user already gone).
     - If transient error: return error (WAL entry retained; rollback retries later).
  5. Compare live `UserInfo.Comment` to `walUser.Nonce`.
     - If `comment == nonce`: this is our orphan; call `client.DeleteUser(userid)`.
     - If `comment != nonce` or `nonce == ""`: log an error and return nil, dropping the WAL entry without deleting the user. This protects foreign/pre-existing users and old malformed WAL entries.
  6. Treat ErrUserNotFound from DeleteUser (body "no such user", HTTP 500) as success.
  7. Return `nil` on success (WAL entry deleted); return error to retry later.

**Accepted risk (document in the file header)**: rollback is deliberately conservative.
If a WAL entry's nonce is empty or does not match the PVE user's `comment`, rollback treats
the user as foreign/ownership-lost, logs the condition, and drops the WAL entry without
deleting the user. This can leak an inert account that requires manual cleanup, but it
prevents WAL rollback from deleting a foreign/pre-existing user after a userid collision.
If `user_id` is missing or empty, rollback returns an error instead of dropping the WAL entry;
operators must inspect/repair/remove that malformed WAL entry because there is no safe PVE
userid to look up or delete.

**References**: `docs/ARCHITECTURE.md` — WAL-Based Orphan Recovery section, walRollback pseudocode.

### TTL computation (no `ttl.go`)

Use `framework.CalculateTTL` from `vault/sdk/framework/lease.go`:

```go
func CalculateTTL(sysView logical.SystemView, increment, backendTTL, period,
    backendMaxTTL, explicitMaxTTL time.Duration, startTime time.Time) (time.Duration, []string, error)
```

It already implements the whole precedence table — `increment` → `backendTTL` →
`sysView.DefaultLeaseTTL()`, capped at `min(backendMaxTTL, sysView.MaxLeaseTTL())`, and capped
again at `startTime + maxTTL` so a renewal cannot outrun the original issue time. It also
treats `0` as *unset* rather than *zero seconds*, which a hand-rolled `min()` gets wrong (an
unset `role.max_ttl` would collapse the effective TTL to 0).

The only helper worth writing is the role-value-or-config-default fallback:

```go
func (r *proxmoxRole) ttls(cfg *proxmoxConfig) (ttl, maxTTL time.Duration) {
    ttl, maxTTL = time.Duration(r.TTL)*time.Second, time.Duration(r.MaxTTL)*time.Second
    if ttl == 0 { ttl = time.Duration(cfg.DefaultTTL) * time.Second }
    if maxTTL == 0 { maxTTL = time.Duration(cfg.DefaultMaxTTL) * time.Second }
    return
}
```

`sysView` is `b.System()`. Call sites: issuance (`path_creds.go`) and renewal
(`secret_token.go`) — see the pseudocode in Credential Lifecycle below.

A second small helper computes the stored `effective_max_ttl`, replacing the inline
`min()` (the Locked Decision forbids hand-rolled `min()`). **Home file: `path_roles.go`**
(same as `ttls()`; both are role-level TTL helpers):

```go
// cappedMaxTTL returns the effective max TTL, treating 0 as "unset" (no cap from that
// source) rather than "zero seconds". If both are unset (0), returns 0 (unlimited),
// which the issuance expire=0 policy then rejects.
func cappedMaxTTL(roleMax, sysMax time.Duration) time.Duration {
    switch {
    case roleMax == 0: return sysMax
    case sysMax == 0:  return roleMax
    default:           return min(roleMax, sysMax)   // Go 1.21+ builtin min on time.Duration
    }
}
```
Unit-test it beside `ttls()`: (roleMax=0,sysMax=X)→X; (X,0)→X; (0,0)→0; (A,B)→min(A,B).

**References**: `docs/ARCHITECTURE.md` — TTL Precedence section.

### `userid.go`

Userid assembly, validation, and random suffix generation.

**Key functions**:
- `buildUserID(prefix, role, suffix, realm string) string` — assembles `{prefix}-{role}-{suffix}@{realm}`. The caller generates the suffix explicitly (via `randomSuffix()`) so the retry loop can control it and replace it on ErrConflict without calling the function twice. Length and component validation happen at role-write time.
- `randomSuffix() (string, error)` — generates 8-character lowercase base32 string from `crypto/rand` (Crockford alphabet: `0123456789abcdefghjkmnpqrstvwxyz`, no padding).
- `validateUserComponent(s string) error` — rejects if `s` is EMPTY, or contains whitespace, `:`, `/`, `@`, or `!`. The `@` and `!` characters break userid/token-header parsing (`<user>@<realm>!<tokenid>` and the `Authorization: PVEAPIToken=<user>@<realm>!<tokenid>=<secret>` header), so they must be rejected in `user_prefix` and role name even though the PVE username regex `[^\s:/]+` alone would permit them. Empty is rejected so `user_prefix` cannot be blank.
- `validateLengthBudget(prefix, role, realm string) error` — checks `len(prefix) + 1 + len(role) + 1 + 8 + 1 + len(realm) <= 64`.

**References**: `docs/ARCHITECTURE.md` — Roles section, synthetic userid format and character set.

### `*_test.go`

Unit test files (one per source file: `path_config_test.go`, `path_roles_test.go`, `path_creds_test.go`, `secret_token_test.go`, `wal_test.go`, `userid_test.go`, plus `internal/pveapi/permission_tree_test.go`). Use the mock client, `logical.TestBackendConfig`, and in-memory storage.

### `acceptance_test.go`

Acceptance tests gated by `VAULT_ACC=1` and run only by an operator via `make testacc`. Required environment variables: `PVE_ADDR`, `PVE_TOKEN_ID`, `PVE_TOKEN_SECRET`, `PVE_TEST_GROUP` (operator must pre-create this group on the test PVE cluster), `PVE_BEHAVIORAL_PATH`, and `PVE_BEHAVIORAL_MARKER`.

**Key tests** (see Testing Plan below).

**References**: `docs/ARCHITECTURE.md` — Testing Strategy section.

## Data Model & Storage

### Config Storage Schema

Stored at storage key `config` (seal-wrapped, encrypted; same literal as `SealWrapStorage`):

```go
type proxmoxConfig struct {
    Address       string `json:"address"`
    TokenID       string `json:"token_id"`        // returned on GET (identity)
    TokenSecret   string `json:"token_secret"`    // NEVER returned on GET
    TLSSkipVerify bool   `json:"tls_skip_verify"`
    CACert        string `json:"ca_cert"`
    DefaultTTL    int    `json:"default_ttl"`
    DefaultMaxTTL int    `json:"default_max_ttl"`
    // NO active_lease_count — engine does not track leases
}
```

### Role Storage Schema

Stored at `roles/<name>`:

```go
type proxmoxRole struct {
    Group      string `json:"group"`
    UserPrefix string `json:"user_prefix"`
    Realm      string `json:"realm"`
    TTL        int    `json:"ttl"`
    MaxTTL     int    `json:"max_ttl"`
}
```

### Lease InternalData Schema

Stored in `Secret.InternalData` for each issued credential:

```go
{
    "pve_userid":        "vault-myrole-a1b2c3d4@pve",  // fixed at issue
    "group":             "vault-vm-admins",            // NEW: target PVE group, fixed at issue; re-sent on renewal (PUT is full-replace); NOT re-derived from role
    "expire":            1672531200,                   // Unix epoch, mutable on renewal
    "role_name":         "myrole",                     // fixed at issue
    "effective_max_ttl": 86400000000000                // nanoseconds, fixed at issue
}
```

`effective_max_ttl` is stored as an `int64` nanosecond duration (the raw `int64(time.Duration)`
value), and renewal converts it with `time.Duration(effective_max_ttl)` before feeding it to
`CalculateTTL` as `backendMaxTTL`. It must NOT be recomputed from the role, which may have
changed since issuance. The lease's own
`req.Secret.IssueTime` supplies `startTime`; `expire` is written for operator/audit
correlation and is not read by renew/revoke. `role_name` IS read by the renew path (to load
the current role for its `ttl` as `backendTTL` only) — if the role has since been deleted,
renewal falls back to `req.Secret.TTL` as the backendTTL and continues (the max is always the
stored `effective_max_ttl`, never the role). `group` is read by the renew path and re-sent on
every `UpdateUser` PUT because PVE `PUT /access/users` is full-replace (Probe 7); it must NOT
be re-derived from the role, which may have been deleted or re-bound.

### WAL Entry Schema

WAL entry at `wal/<uuid>` (kind `"user"`):

```go
type walUser struct {
    UserID string `json:"user_id" mapstructure:"user_id"`
    Nonce  string `json:"nonce" mapstructure:"nonce"`
}
```

`Nonce` is the full prefixed value `vault-wal:<8-character random suffix>` and must exactly
match the PVE user's `comment` field for WAL rollback to delete the user. This nonce-gated
ownership contract is separate from revocation idempotency; revoke still treats `DeleteUser`
returning body `"no such user"` as success.

**References**: `docs/ARCHITECTURE.md` — Storage Schema section, lease internalData, WAL-Based Orphan Recovery section.

## Credential Lifecycle

### Issuance (handleCredsRead)

ALL work happens BEFORE returning the Secret to the caller (no post-lease-write hook exists).

**Pseudocode**:

**SDK signatures** (`vault/sdk/framework/wal.go`) — `PutWAL` returns the WAL **ID string**, and
`DeleteWAL` takes that id, NOT the kind + payload:

```go
func PutWAL(ctx context.Context, s logical.Storage, kind string, data interface{}) (string, error)
func DeleteWAL(ctx context.Context, s logical.Storage, id string) error
```

Every attempt therefore has to keep its own `walID`.

```
1. Load role from storage (roles/<role>), nil entry → "role not found"
2. Load config from storage (config), nil entry → "config not set"
3. Build client (cached via getClient)
4. roleTTL, roleMaxTTL := role.ttls(cfg)
   effTTL, warnings, err := framework.CalculateTTL(
       b.System(), 0, roleTTL, 0, roleMaxTTL, 0, time.Time{})
   - err → return error
   - (warnings are surfaced on the response at step 10 via resp.AddWarning(warnings...))
   -      effMaxTTL := cappedMaxTTL(roleMaxTTL, b.System().MaxLeaseTTL())   // named helper, treats 0 as unset
     (this is the value stored as effective_max_ttl and fed back on renewal)
5. If effTTL == 0: return error "role %q resolves to an unlimited TTL; the PVE expire
   backstop requires a finite lease — set a non-zero ttl/max_ttl" (Locked Decision:
   expire=0 policy). Issuance MUST NOT proceed with an unlimited TTL.
   Note: because `framework.CalculateTTL` falls back to `sysView.DefaultLeaseTTL()` (which is
   non-zero on any real Vault server), `effTTL == 0` is effectively unreachable in production.
   The guard is correct and cheap — keep it as belt-and-braces defense-in-depth, not a live
   branch; testing it requires a mock `SystemView` returning zero defaults.
   Otherwise:
   - leaseExpiry := time.Now().Add(effTTL + expireGrace).Unix()   // expireGrace = 60s
   Rationale: the PVE `expire` is a BACKSTOP, so it must land AFTER the Vault lease ends —
   a PVE node clock running ahead of the Vault host would otherwise 401 a live credential.
   We never send expire=0, because a never-expiring user disables the backstop entirely.
6. Retry loop (bound = 5 attempts):
   a. suffix, err := randomSuffix()
      - If err: return error
   b. userid := buildUserID(role.UserPrefix, roleName, suffix, role.Realm)
   c. rawNonce, err := randomSuffix(); nonce := walCommentPrefix + rawNonce
   d. walID, err := framework.PutWAL(ctx, req.Storage, walTypeUser, walUser{UserID: userid, Nonce: nonce})
       - If err: return error (nothing created yet; nothing to clean up)
    e. CreateUser({UserID: userid, Groups: role.Group, Expire: leaseExpiry, Enable: true, Comment: nonce})  // single CSV groups field; comment is WAL ownership marker
    f. If ErrConflict (mapped from HTTP 500 + body "already exists" — NOT a 409):
       - If framework.DeleteWAL(ctx, req.Storage, walID) fails: return error (abort issuance; nonce-gated rollback will not delete the foreign colliding user)
       - continue loop (try new suffix)
    g. If other error (non-Conflict):
       // PVE may or may not have committed the user before the response failed
       // (timeout/5xx). Leave the WAL entry in place and return the CreateUser
       // error; walRollback will later GetUser(userid), drop the WAL if the user
       // was never committed (ErrUserNotFound), or delete it only if the live
       // comment still equals nonce. Do NOT inline DeleteUser here.
       - return error (WAL retained for rollback)
   h. If success:
      READ-BACK ASSERT (PVE silently drops unresolvable group ids with HTTP 200 on modify/append; on create, PVE instead REJECTS with HTTP 500 "no such group" — the read-back assertion covers both paths):
             - info, err := GetUser(userid)
             - if err or role.Group NOT in info.Groups:
                // NOTE: this fails closed — a transient GetUser error is treated the same as a
                // confirmed-absent group (both tear down the user). Acceptable for correctness;
                // for future retry/metrics, distinguish "group confirmed absent in a successful
                // GetUser" from "GetUser errored (couldn't confirm)" in the log/error message.
                - delErr := DeleteUser(userid)
                 - if delErr == nil OR errors.Is(delErr, pveapi.ErrUserNotFound):
                      // user is gone (or never persisted) → safe to drop the WAL entry
                      framework.DeleteWAL(ctx, req.Storage, walID) [best-effort]
                - else:
                      // DeleteUser failed transiently — LEAVE the WAL entry so walRollback
                      // retries the cleanup. Do NOT DeleteWAL here (would orphan the user).
                      // (walID still points at this userid.)
                 - return error "group membership not reflected after create (group %q may be unresolvable on cluster)"
                   (wrap delErr if non-nil/non-ErrUserNotFound so the operator sees the cleanup failure)
             - if info.Comment != nonce: add a warning (non-fatal): WAL crash-recovery cleanup for this user may be disabled because the PVE comment did not preserve the nonce; direct revoke is unaffected.
       - break loop (keep walID for steps 8–9)
7. If loop exhausted (5 attempts all ErrConflict): return internal error "userid collision after 5 retries"
8. tokenSecret, err := CreateToken(userid, "lease")  // client always sends wire form value privsep=0
   - If ErrConflict (mapped from HTTP 400 + body "Token already exists" — NOT a 409):
       // Not expected: each lease has a unique fresh userid, and token ids are scoped
       // per-user. A conflict here is on OUR OWN freshly-created user — it does NOT
       // belong to a different active lease. Treat it like any other CreateToken error.
       - delErr := DeleteUser(userid) [best-effort cleanup of the user we just created]
       - if delErr == nil OR errors.Is(delErr, pveapi.ErrUserNotFound):
             framework.DeleteWAL(ctx, req.Storage, walID) [best-effort]
       - else:
             // DeleteUser failed transiently — LEAVE the WAL entry for walRollback to retry.
             // Do NOT DeleteWAL.
        - return internal error "token conflict on freshly-created userid (unexpected)" (wrap delErr if non-nil/non-ErrUserNotFound)
   - Else if err (any other error):
       - delErr := DeleteUser(userid) [best-effort cleanup of the user we just created]
       - if delErr == nil OR errors.Is(delErr, pveapi.ErrUserNotFound):
             framework.DeleteWAL(ctx, req.Storage, walID) [best-effort]
       - else:
             // DeleteUser failed transiently — LEAVE the WAL entry for walRollback to retry.
             // Do NOT DeleteWAL.
        - return error (wrap delErr if it was non-nil/non-ErrUserNotFound)
9. err := framework.DeleteWAL(ctx, req.Storage, walID)
   - If DeleteWAL fails:
     - DeleteUser(userid) [best-effort cleanup]
     - return error (NO Secret returned; caller retries from scratch)
     // Note: here the WAL entry is (by definition) still present because DeleteWAL
     // failed, so best-effort DeleteUser + error is correct: if DeleteUser also fails,
     // walRollback still owns this userid and will retry. No conditional needed — we
     // are NOT attempting a second DeleteWAL.
10. resp := b.Secret(secretTypeToken).Response(
        map[string]interface{}{  // Data
            "user_id": userid, "token_id": userid+"!lease", "token_secret": tokenSecret},
        map[string]interface{}{  // InternalData
            "pve_userid": userid, "group": role.Group, "expire": leaseExpiry, "role_name": roleName,
            "effective_max_ttl": int64(effMaxTTL)})  // nanoseconds
    resp.Secret.TTL = effTTL
    resp.Secret.MaxTTL = effMaxTTL
    for _, w := range warnings { resp.AddWarning(w) }   // surface CalculateTTL warnings
11. Return response
```

**Key points**:
- Each retry writes a NEW WAL entry (new id) for the NEW userid, and deletes the abandoned attempt's entry by ITS id on ErrConflict (per-attempt WAL ordering).
- Each WAL payload uses kind `"user"` and keys `user_id` and `nonce`. The nonce is `vault-wal:<8-character random suffix>` and equals the PVE user `comment`.
- Token creation ErrConflict is NOT expected (each lease has a unique userid; token ids are scoped per-user). If it occurs, treat it like any other CreateToken error: best-effort DeleteUser, then DeleteWAL ONLY if DeleteUser returned nil or ErrUserNotFound.
- If `DeleteWAL` fails (step 9), the issuance MUST fail and clean up the user — no Secret is returned, preventing WALRollback from racing a live credential.
- `framework.Secret.Response` sets `Renewable = (s.Renew != nil)`, so the secret is renewable purely because `secretToken(b)` registers a `Renew` callback — nothing to set by hand.
- After CreateUser, the handler MUST read the user back (`GetUser`) and assert the target group appears in `.Groups`; PVE returns HTTP 200 even when it silently drops an unresolvable group id (observed on modify/append; on create, PVE instead REJECTS with HTTP 500 `"no such group"` — the read-back assertion covers both paths). Verifiable equivalently via `GET /access/groups/{id}.members`.

**References**: `docs/ARCHITECTURE.md` — Implementation Notes — Service API Calls (Create ordering), Issuance ordering detail, userid collision retry, token creation conflict, privsep=0, WAL-Based Orphan Recovery section.

### Renewal (secretTokenRenew)

**Pseudocode**:

```
1. Read pve_userid, group, role_name, effective_max_ttl from req.Secret.InternalData (group is REQUIRED — renewal re-sends it; do NOT re-derive from the role, which may be gone/re-bound. role_name is used only to load the role for its ttl.)
2. storedMaxTTL := time.Duration(effective_max_ttl)
   // DECODE DISCIPLINE: InternalData values (effective_max_ttl, expire) round-trip through
   // JSON storage and come back as float64, NOT int/int64 — a direct `.(int64)` type
   // assertion PANICS/fails (same trap documented for WAL decode, wal.go step 2 / line 450).
   // Read them as float64 then convert as nanoseconds: e.g.
   //   emtRaw, _ := req.Secret.InternalData["effective_max_ttl"].(float64)
   //   storedMaxTTL := time.Duration(int64(emtRaw))
   // Likewise pve_userid/group/role_name assert to string.
3. Load config from storage (config). If missing, return error.
   Build client (via getClient).
4. Load role by role_name for its ttl → roleTTL := role.ttls(cfg) ttl-component. If the role is GONE, fall back to roleTTL := req.Secret.TTL. Used ONLY as backendTTL, never as the max.
5. newTTL, warnings, err := framework.CalculateTTL(
       b.System(), req.Secret.Increment, roleTTL, 0, storedMaxTTL, 0, req.Secret.IssueTime)
   - err → return error (includes "past the max TTL, cannot renew")
   - (warnings surfaced at step 10 via resp.AddWarning(warnings...))
6. If newTTL == 0: return error "renewal resolves to an unlimited TTL; refusing (expire
   backstop requires a finite lease)" — mirrors the issuance expire=0 policy. This should
   not occur for a lease that issued with a finite TTL, but guard it.
   Otherwise:
   - newExpiry := time.Now().Add(newTTL + expireGrace).Unix()   // finite; never 0
7. Pre-update GetUser(pve_userid): if Enable == false, refuse renewal so an operator's
   out-of-band disable remains an incident-response kill switch. If GetUser returns
   ErrUnauthenticated, wrap with the admin-token diagnostic; if it returns ErrUserNotFound,
   renewal fails and the lease expires.
8. UpdateUser({UserID: pve_userid, Expire: newExpiry, Groups: group, Enable: true, Append: true})
   // Historical Probe 7 showed replacement-style updates can wipe groups; a later live
   // acceptance run preserved groups when append was omitted. Omitted-append semantics are
   // unresolved, so renewal MUST re-send expire+groups+enable+append=1 together.
   // The pre-update GetUser check prevents re-enabling a user that was already disabled.
   // TOCTOU: if an operator disables the user between pre-check and UpdateUser, this PUT can
   // still re-enable it; PVE has no conditional-update API to close that race.
   - If ErrUnauthenticated (HTTP 401): wrap with "admin token unauthenticated — check config credentials" while preserving errors.Is.
   - If ErrUserNotFound (body "no such user"): return error "user no longer exists" (renewal fails; lease expires)
   - If other error: return error (Vault retries renewal)
8b. READ-BACK ASSERT: info, err := GetUser(pve_userid);
    if err or group NOT in info.Groups: return error "group membership not preserved across renewal"
9. req.Secret.InternalData["expire"] = newExpiry
10. resp := &logical.Response{Secret: req.Secret}
   resp.Secret.TTL = newTTL
   resp.Secret.MaxTTL = storedMaxTTL
   for _, w := range warnings { resp.AddWarning(w) }   // surface CalculateTTL warnings
11. Return resp
```

**Key points**:
- **`max_ttl` runs from `IssueTime`, not from now.** Capping the renewal at `min(requested, effective_max_ttl)` measured from the current time lets a lease live roughly 2× its `max_ttl`. `framework.CalculateTTL` handles this correctly given `startTime = req.Secret.IssueTime` (populated by core on renew — see the `IssueTime` comment in `sdk/logical/lease.go`).
- Use stored `effective_max_ttl` from issuance time as `backendMaxTTL`; do NOT recompute the max from the role (role may have changed). Only `backendTTL` may come from the current role.
- Return `&logical.Response{Secret: req.Secret}` — the mutated `InternalData["expire"]` persists only because core stores the returned Secret back onto the lease entry.
- `UpdateUser` re-sends `expire`+`groups`+`enable`+`append=1` on every renewal PUT. Historical PVE 9.2.10 Probe 7 showed replacement-style updates can wipe the groups array, stripping the credential's effective privileges; a later live acceptance run preserved groups when `append` was omitted, so omitted-`append` semantics are unresolved. The target group is read from lease InternalData (`group`), not the role. A read-back (`GetUser`) MUST confirm membership survived.

**References**: `docs/ARCHITECTURE.md` — Lease Renewal section, TTL Precedence section (renewal note).

### Revocation (secretTokenRevoke)

**Pseudocode**:

```
1. Read pve_userid from req.Secret.InternalData
2. Load config, build client
3. DeleteUser(pve_userid)
   - If ErrUserNotFound (body "no such user", HTTP 500): return nil (idempotent success)
   - If other error: return error (Vault retries revocation)
4. Return nil
```

**Key points**:
- ErrUserNotFound (body "no such user", HTTP 500) is success (idempotent).
- Vault's revocation retry handles transient failures.
- Single delete cascades to tokens, group memberships, ACL entries.

**References**: `docs/ARCHITECTURE.md` — Revocation section, idempotency (body "no such user" on HTTP 500 treated as success).

## WAL Rollback

Registered via `backend.WALRollback` and `backend.WALRollbackMinAge = 5 * time.Minute`.

**Pseudocode (`walRollback`)**:

```
1. If kind != walTypeUser: return fmt.Errorf("unknown WAL kind: %s", kind)
2. Decode data (map[string]interface{}) into walUser via mapstructure/JSON round-trip. Required keys are `user_id` and `nonce`; no compatibility aliases.
   - If `user_id` is missing or empty: return error (WAL entry retained; rollback retries/alerts).
3. Load config, build client (if config missing, return error → retry later)
4. GetUser(walUser.UserID)
   - If ErrUserNotFound (body "no such user", HTTP 500): return nil (WAL entry deleted; user already cleaned up or never existed)
   - If other error: return error (WAL entry retained; rollback retries later)
5. Verify ownership by comparing `info.Comment == walUser.Nonce`.
   - If true: DeleteUser(walUser.UserID); ErrUserNotFound from DeleteUser is success.
   - If false, or if `walUser.Nonce == ""`: log an error and return nil, dropping the WAL entry without deleting the user.
6. Return nil after successful delete; return any transient delete error for retry.
```

**Division of responsibility**:
- **WALRollback**: Cleans up users orphaned by crash/failover BETWEEN `PutWAL` and `DeleteWAL` (i.e., WAL entry exists but issuance never completed, no Secret returned, no lease registered). It ALSO catches users left behind when an in-line cleanup `DeleteUser` fails transiently: the issuance path deletes its WAL entry ONLY when `DeleteUser` returns nil or `ErrUserNotFound`; if `DeleteUser` fails otherwise, the WAL entry is deliberately RETAINED and the error is returned so walRollback retries the delete. Before deleting, WALRollback verifies ownership by reading the PVE user and requiring the live `comment` to equal the WAL `nonce` (`vault-wal:<8-char-random>`). A missing/empty `user_id` is an error/retry condition because there is no safe lookup target. An empty or mismatched nonce is terminal for rollback: log and drop the WAL entry without deleting the user. This preserves safety for foreign users while keeping revoke idempotency separate.

  **Accepted risk — crash between `DeleteWAL` and lease persistence**: there is ONE window this does not cover: a crash between the successful `DeleteWAL` (issuance step 9) and Vault core persisting the returned Secret/lease. In that narrow window the WAL entry is already gone and no lease exists, so neither WALRollback nor Vault revocation fires. The PVE `expire` backstop (set to lease-end + grace at creation time) only **neutralizes** the credential — authentication is rejected once past `expire` (Probe 8) — it does **NOT** delete the user; PVE has no auto-reap, so the stale user record **persists in user.cfg until out-of-band cleanup**. This window is therefore a leak of an inert (auth-rejected) but undeleted user, not a live credential. Requires a crash inside that narrow window. Documented, not mitigated.
- **Vault revocation retry**: Handles failed revocations on existing leases.
- **PVE `expire` backstop**: neutralizes any leaked user that slips through both — authentication is rejected once past `expire` (Probe 8) — but does NOT delete the user record (persists until out-of-band cleanup).

**References**: `docs/ARCHITECTURE.md` — WAL-Based Orphan Recovery section, division of responsibility.

## TTL Precedence

Delegated to `framework.CalculateTTL` (`vault/sdk/framework/lease.go`). The engine only
supplies the role-or-config-default fallback (`role.ttls(cfg)`); everything else — system
default, system max ceiling, unset-vs-zero, and the from-`IssueTime` renewal cap — is already
implemented there and must not be re-derived:

```go
// Issuance
ttl, warns, err := framework.CalculateTTL(b.System(), 0, roleTTL, 0, roleMaxTTL, 0, time.Time{})

// Renewal
ttl, warns, err := framework.CalculateTTL(b.System(), req.Secret.Increment, roleTTL, 0,
                                          storedMaxTTL, 0, req.Secret.IssueTime)
```

**Capture at issuance**: Store `effective_max_ttl` in `Secret.InternalData["effective_max_ttl"]` as an `int64` nanosecond duration (`int64(effectiveMaxTTL)`). All renewals convert it with `time.Duration(stored)` and pass this stored value as `backendMaxTTL`, NOT recomputed from the role.

**Key points**:
- Config `default_ttl` and `default_max_ttl` are fallbacks when role values unset.
- `0` means *unset*, not *zero seconds*. A hand-rolled `min()` gets this wrong: an unset `role.max_ttl` collapses the effective TTL to 0. `CalculateTTL` falls back to `sysView.DefaultLeaseTTL()` / `MaxLeaseTTL()`.
- Vault mount/system max is the absolute ceiling.
- There is no issuance-time requested TTL (`creds/:role` declares no `ttl` field), so `increment` is 0 at issuance and `req.Secret.Increment` on renewal.
- Renewal caps against `IssueTime + effective_max_ttl`, not `now + effective_max_ttl`.

**References**: `docs/ARCHITECTURE.md` — TTL Precedence section.

## Testing Plan

### Unit Tests (with Mock Client)

| File | Coverage |
|------|----------|
| `path_config_test.go` | Config write (validation, client build, GetVersion, GetPermissions ancestor-walk — injected via `b.newClient` func field, see mock-seam note in `path_config.go` section); config read (excludes token_secret); config delete (requires force=true, rejects without it) |
| `path_roles_test.go` | Role write (ttl validation, userid budget, GetGroup ErrGroupNotFound via 500+body "does not exist", GetPermissions realm check, per-group-path User.Modify check at /access/groups/<group> (propagate=0 → reject)); role read/list/delete |
| `path_creds_test.go` | Full issuance flow (WAL ordering, CreateUser ErrConflict via 500+body "already exists" drives retry, group read-back-failure injection (GetUser returns groups:[] → issuance errors, user+WAL cleaned up, no Secret); token ErrConflict via 400+body "Token already exists" → best-effort DeleteUser + conditional DeleteWAL (same as any other CreateToken error); collision exhaustion after 5 attempts); **DeleteWAL-failure injection** (see below); `expire` = lease end + grace; issuance is REFUSED when the effective TTL resolves to 0 (unlimited) — `expire=0` can never reach the wire (the guard fires first; `framework.CalculateTTL` falls back to `sysView.DefaultLeaseTTL()` so `effTTL == 0` is effectively unreachable in practice — the guard is belt-and-braces, correct and cheap, but testing it requires a mock `SystemView` returning zero defaults) |
| `secret_token_test.go` | Renewal (`CalculateTTL` capped from `IssueTime` — a renew requested near `max_ttl` on an old lease gets the remainder, not a full increment; UpdateUser re-sends expire+groups+enable+append; read-back asserts group preserved; group read from InternalData not role; ErrUserNotFound(500+body) → fail); revocation (DeleteUser, ErrUserNotFound(500+body) → success) |
| `wal_test.go` | walRollback (decodes `map[string]interface{}` payload with `user_id`+`nonce`; missing/empty `user_id` → error/retry; GetUser ErrUserNotFound (500+body "no such user") → success; matching comment/nonce → DeleteUser; comment mismatch or empty nonce → log/drop WAL without delete; DeleteUser error → retry; unknown kind → error) |
| `userid_test.go` | buildUserID format; randomSuffix entropy/charset; validateUserComponent (rejects empty, `:`, `/`, whitespace, `@`, `!`); validateLengthBudget (rejects >64) |
| `internal/pveapi/permission_tree_test.go` | `HasPrivilege` ancestor-walk: exact path with propagate=0 → true; ancestor with propagate=1 → true; **ancestor with propagate=0 → false**; root grant; missing path |
| `internal/pveapi/errors_test.go` (NEW) | `classifyPVEError` fed the ACTUAL probed bodies (PVE_PROBES.md Probes 2–6b): 500 `{"data":null,"message":"create user failed: user 'x@pve' already exists\n"}`→ErrConflict; **400 `{"message":"Parameter verification failed.\n","data":null,"errors":{"tokenid":"Token already exists."}}`→ErrConflict (asserts the match reads `errors.tokenid`, NOT `message`)**; 500 `{"data":null,"message":"no such user ('x@pve')\n"}`→ErrUserNotFound; 500 `{"data":null,"message":"group 'g' does not exist\n"}`→ErrGroupNotFound; 500 `{"data":null,"message":"create user failed: no such group 'vault-test-grp'\n"}`→ErrGroupNotFound; 403 (any body)→ErrForbidden; trailing-`\n` / embedded-quoted-id tolerance |
| `internal/pveapi/client_test.go` (NEW) | `httptest`-based: assert the **real** HTTP client serializes `privsep=0` as the literal string `"0"` (not `"false"` or omitted) on `POST .../token/{tokenid}`; `enable=1` as `"1"` on `POST /access/users`; `append=1` as `"1"` on `PUT /access/users/{userid}`; `groups` as ONE comma-separated form field (never array-repeated) on user create/update. Also assert `classifyPVEError` body-string mapping via the same probed bodies used in `errors_test.go`. Assert that `token_secret` never appears in any error string returned by the client. |

Use `logical.TestBackendConfig` and in-memory storage (`framework.Storage` from `vault/sdk`). Mock client is programmable (inject ErrConflict on attempt N, ErrGroupNotFound on GetGroup, etc.).

**DeleteWAL-failure injection** belongs here, not in the acceptance suite: `framework.DeleteWAL`
is a package function with no injection seam, but it takes a `logical.Storage`. Wrap the
in-memory storage in a decorator that returns an error from `Delete` for keys under the `wal/`
prefix, then assert (a) issuance returns an error with no Secret, and (b) the mock client
recorded a `DeleteUser` for the just-created userid. No live PVE needed.

**Group read-back-failure injection** also belongs here (no live PVE needed): program the mock `GetUser` to return `Groups: []` (simulating PVE's silent group-drop behaviour, confirmed via PVE_PROBES.md GROUPADD) after a successful `CreateUser`. Assert (a) issuance returns an error naming the group, (b) no Secret is returned, and (c) the mock recorded a `DeleteUser` for the userid and a `DeleteWAL` for its WAL id.

### Acceptance Tests (VAULT_ACC=1)

**Environment variables**:
- `PVE_ADDR` — Proxmox API endpoint (e.g., `https://pve.example.com:8006`)
- `PVE_TOKEN_ID` — admin token ID (e.g., `vault-admin@pve!root-token`)
- `PVE_TOKEN_SECRET` — admin token secret
- `PVE_TEST_GROUP` — operator-pre-created PVE group bound to a test role (operator must create this out-of-band before running tests)
- `PVE_BEHAVIORAL_PATH` — group-role-gated endpoint for the authorization canary
- `PVE_BEHAVIORAL_MARKER` — response marker required from the behavioral endpoint

**Gating**: Tests prefixed `TestAcc*` run ONLY when `VAULT_ACC=1` (HashiCorp convention). The canonical operator command is `make testacc`, which preflights only the required variables above (`PVE_BEHAVIORAL_PATH` must be a group-role-gated endpoint, not `/version`) and then runs `VAULT_ACC=1 go test -count=1 -v -timeout=30m ./... -run TestAcc`.

**Harness (concrete)**:
- **Vault instantiation**: acceptance tests DO NOT spin up a real Vault server. They construct the backend directly with `logical.TestBackendConfig()` + in-memory `logical.Storage`, call `Factory(ctx, config)`, and drive it through `logical.Request`s (same pattern as unit tests). The difference from unit tests is that the *pveapi.Client is the REAL client pointed at a live PVE cluster (not the mock). A full `vault server -dev` end-to-end run is the manual smoke test (Build & Run section), not an automated `TestAcc`.
- **PVE cluster source**: OPERATOR-PROVIDED and MANUAL. There is no official Proxmox VE container image suitable for CI, so the target 9.2.10 cluster is stood up out-of-band by the operator and supplied via `PVE_ADDR`/`PVE_TOKEN_ID`/`PVE_TOKEN_SECRET`/`PVE_TEST_GROUP` plus the behavioral canary variables. Local tests skip (not fail) when `VAULT_ACC` is unset OR the env vars are absent. `make testacc` intentionally fails during preflight when required live variables are absent so operators do not accidentally run a degraded live suite.

**Test scenarios**:

| Test | Assertions |
|------|-----------|
| `TestAccLifecycle` | Write config → write role → read creds → use issued token for `/version` authentication smoke (not proof of group privilege) → renew → verify renewed → revoke → verify user deleted by asserting `GET /access/users/{userid}` returns the PVE body "no such user" (HTTP 500, NOT 404). Do NOT assert status 404. |
| `TestAccAuthorizationContractCanary` | **Required behavioral canary plus optional negative/ACL probes** (see `docs/ARCHITECTURE.md` Acceptance Tests section — Authorization contract canary):<br/>a. Require `PVE_BEHAVIORAL_PATH` and `PVE_BEHAVIORAL_MARKER`; use the issued privsep=0 token to call the group-role-gated endpoint and assert HTTP 200 plus marker in the body. This is the authoritative oracle; bare `/version` success is only an auth smoke check.<br/>b. Optional: admin token attempts `PUT /access/acl` to grant an unheld role → 403 when `PVE_ACL_CANARY_*` variables are configured.<br/>c. Create user with `expire` in the past, verify token authentication returns 401.<br/>d. Create user, renew with `PUT /access/users/{userid}` re-sending `expire`+`groups`+`enable`+`append=1`. Assert via read-back that `groups` still contains the group after renewal. Add a CONTROL intended to exercise explicit replacement (`groups=` with `append=0`) on a throwaway user that already has the group; the expected outcome is `groups:[]` pending live confirmation.<br/>e. Optional: negative authorization endpoint returns 403 when `PVE_NEGATIVE_AUTH_PATH` is configured. |
| `TestAccRevocationIdempotencyAfterOutOfBandDelete` | Issue credential, delete the issued PVE user out-of-band, then revoke the Vault secret → verify PVE body "no such user" (HTTP 500) is treated as success. Live acceptance does NOT inject network failures; mid-provisioning network/error injection and DeleteWAL-failure injection live in unit tests (`path_creds_test.go`) with mock client/storage seams. |
| `TestAccWALRollback` | Write config+role → create `nonce := walCommentPrefix + <8-char-random>` → manually `framework.PutWAL(ctx, storage, walTypeUser, walUser{UserID: userid, Nonce: nonce})` → manually `client.CreateUser(userid)` with `comment=nonce` → **invoke `b.walRollback(ctx, req, walTypeUser, walEntryData)` DIRECTLY** (there is NO `PeriodicFunc` on this backend — rollback is registered via `backend.WALRollback`, and in a live Vault it fires on the rollback manager's schedule; the test calls the func directly rather than waiting) → verify `DeleteUser` ran and the user is gone on PVE (assert `GET` returns body "no such user"). Because `walRollback` receives `data interface{}` holding a `map[string]interface{}`, construct the call arg the same JSON-round-tripped way core would (see wal.go decode note). |
| `TestAccConcurrentIssuance` | Spawn 10 goroutines by default (configurable 1–10 with `PVE_CONCURRENT_WORKERS`), each calls `creds/:role` concurrently → verify all succeed (no collision errors, ErrConflict retry works). Every issued credential is revoked and absence-verified, and WAL rollback cleanup is attempted on all paths. If a disposable/dev cluster cannot safely sustain default load, lower the worker env var rather than weakening the success assertion. |
| `TestAccDeleteConfigGuard` | Write config → DELETE without `force=true` → assert refused with clear error;<br/>DELETE with `force=true` → assert succeeds and config gone. Also confirms `force` actually reaches the handler as a query param through whatever client the test uses |

**References**: `docs/ARCHITECTURE.md` — Testing Strategy section, Acceptance Tests — authorization contract canary, failure injection, DELETE config guard.

### Password Credential Testing Strategy (gated)

Password tests remain pending until P0 records live PVE 9.2.10 behavior. Unit tests
must use the mock client and assert the contract without exposing password values in
test logs or failure messages. They must cover mode defaulting and validation, the
separate secret schema, password-only issuance with no token call, compensation and
WAL ordering, renewal without rotation or password return, revocation, and
compatibility with token roles and pre-existing token leases. Acceptance coverage
must be opt-in and operator-run against the probed PVE behavior, including password
authentication, expiry, disablement, deletion, and any confirmed interaction with
token credentials. No password acceptance test may run before P0 is complete.

## Build & Run

### Build the Plugin

```bash
make build
```

Outputs to `vault/plugins/vault-plugin-secrets-proxmox`.

### Dev Vault Server with Plugin

```bash
# Terminal 1: Start dev Vault with plugin dir
vault server -dev -dev-root-token-id=root -dev-plugin-dir=./vault/plugins

# Terminal 2: Set env
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='root'

# NOTE: -dev-plugin-dir auto-registers every binary in that directory into the plugin
# catalog at startup, so no `vault plugin register -sha256=...` step is needed here.
# For a NON-dev server, register explicitly instead:
#   SHA256=$(shasum -a 256 vault/plugins/vault-plugin-secrets-proxmox | cut -d' ' -f1)
#   vault plugin register -sha256="$SHA256" secret vault-plugin-secrets-proxmox

# Enable at mount path
vault secrets enable -path=proxmox vault-plugin-secrets-proxmox

# Write config
vault write proxmox/config \
    address="https://pve.example.com:8006" \
    token_id="vault-admin@pve!root-token" \
    token_secret="<secret>" \
    ca_cert=@/path/to/ca.pem \
    default_ttl=3600 \
    default_max_ttl=86400

# Write role
vault write proxmox/roles/vm-admin \
    group="vault-vm-admins" \
    user_prefix="vault" \
    realm="pve" \
    ttl=3600 \
    max_ttl=7200

# Read credentials
vault read proxmox/creds/vm-admin

# Renew lease
vault lease renew <lease_id>

# Revoke lease
vault lease revoke <lease_id>

# Delete config (requires force=true; K=V on `vault delete` needs CLI >= 1.11 and is
# transmitted as a query parameter)
vault delete proxmox/config force=true

# Fallback for older CLIs:
curl -sS -X DELETE -H "X-Vault-Token: $VAULT_TOKEN" \
  "$VAULT_ADDR/v1/proxmox/config?force=true"

# NAME COLLISION (DR-5): `vault delete -force` is a Vault CLI FLAG that only
# skips the interactive confirmation prompt. It sends NO `force` data value, so
# the command below is REJECTED by the guard with "requires force=true":
#   vault delete -force proxmox/config          # WRONG — flag, not data param
# The `force` here is a DATA parameter and must be passed as a K=V pair (or as
# an explicit query parameter via curl). The field keeps the name `force`
# because the documented API surface (README, AGENTS.md, ARCHITECTURE.md) and
# operator runbooks already use `force=true`; the collision is resolved by
# documentation (field Description + README + the guard's rejection message)
# rather than by a non-standard field name such as `confirm_delete`.
```

### Smoke Test

After building and registering:

1. Enable mount
2. Write config (should succeed if admin token has privileges)
3. Write role (should succeed if group exists)
4. Read creds (should return `user_id`, `token_id`, `token_secret`)
5. Use issued token to call PVE API (verify it works)
6. Renew lease
7. Revoke lease (verify user deleted on PVE)
8. Delete config with `force=true` (should succeed)

**References**: `docs/ARCHITECTURE.md` — Root Rotation section (manual operation).

## Phased Task List

### Phase 0 — Spike / Ground-Truth Probes (COMPLETE)

**Status**: ✅ DONE. See `docs/PVE_PROBES.md` for the full evidence.

Phase 0 captured live PVE 9.2.10 HTTP behavior that the rest of the plan branches on
(error contract is body-string not status-code; single-call `groups=<CSV>` create lands
membership with mandatory read-back; `PUT /access/users` is full-replace; permissions tree
inner value is the propagate flag; expired-user token → 401; propagate=0 detectable at the
exact path). These findings are load-bearing and supersede any conflicting "confirmed"
annotations elsewhere. No code deliverable — this phase gated the design.

---

### Phase 1 — Bootstrap + Proxmox Client + Config Path

**Status**: ✅ COMPLETE — implemented and covered by unit tests.

**Tasks**:
- [x] Create `go.mod` (module path `github.com/hazmei/vault-plugin-secrets-proxmox`, go 1.25.7 — bumped from 1.23 to satisfy sdk v0.25.1 minimum, require `vault/sdk v0.25.1` + `go-hclog v1.6.3`)
- [x] Create `.gitignore` (Go + Vault plugin artifacts)
- [x] Create `Makefile` (build/test/testacc/fmt/lint/tidy targets)
- [x] Create `.golangci.yml` (v2 schema — see Bootstrap Files)
- [x] Create `cmd/vault-plugin-secrets-proxmox/main.go` (~15 lines; moved up from Phase 6 so the plugin is buildable and registerable from the first phase)
- [x] Implement `internal/pveapi/errors.go` (ErrUserNotFound/ErrGroupNotFound/ErrConflict/ErrForbidden/ErrUnauthenticated — no RetryableError)
- [x] Implement `internal/pveapi/types.go` (PermissionTree with HasPrivilege ancestor-walk, propagate-flag aware)
- [x] Implement `internal/pveapi/client.go` (Client interface + real impl: GetVersion, GetPermissions, GetGroup, CreateUser, GetUser, CreateToken, UpdateUser, DeleteUser; auth header; TLS config; classifyPVEError body-string mapping; explicit `privsep=0`/`enable=1` form values; no secrets in error strings)
- [x] Implement `internal/pveapi/mock.go` (programmable mock client for tests)
- [x] Implement `backend.go` (Factory, newBackend, getClient cached, invalidate)
- [x] Implement `path_config.go` (POST: validate default_ttl<=default_max_ttl, GetVersion, GetPermissions + ancestor-walk for User.Modify+Sys.Audit @ /access/groups, store seal-wrapped at key `config`; GET: return all except token_secret; DELETE: require `force=true` via a declared TypeBool field)
- [x] Unit tests: `path_config_test.go` (write validation + permission checks, read excludes secret, delete guard)
- [x] Unit tests: `internal/pveapi/permission_tree_test.go` (ancestor-walk cases incl. ancestor with propagate=0 → false)
- [x] Unit tests: `internal/pveapi/errors_test.go` (classifyPVEError body-string mapping fed ACTUAL probed bodies incl. 400 `errors.tokenid` "Token already exists" — see Testing Plan table; asserts match reads full body not just `message`)
- [x] Unit tests: `internal/pveapi/client_test.go` (httptest-based wire-encoding: assert real client sends `privsep=0` as literal `"0"`, `enable=1` as `"1"`, `append=1` as `"1"`, `groups` as ONE comma-separated form field never array-repeated; assert `token_secret` never appears in error strings)

**Acceptance Criteria**:
- `go build ./...` succeeds (no compile errors)
- Config write/read/delete unit tests pass
- Permission ancestor-walk unit tests pass (exact path, ancestor with propagate=1, ancestor with propagate=0 rejected, root grant)
- classifyPVEError unit tests pass (incl. the `errors.tokenid` case matching on full body)
- Client wire-encoding test (`client_test.go`) asserts `privsep=0`/`enable=1`/`append=1`/`groups`-CSV on the wire and confirms `token_secret` never appears in error strings

**Architecture References**: `docs/ARCHITECTURE.md` Configuration section, Required privilege scoping, ancestor-path walk (Implementation note on permission-tree ancestor walk), DELETE config behavior.

**Phase 1 post-review fixes applied**: Jester consensus review surfaced 5 fixes applied in commit `d6f9cb3` — HTTPS enforcement on config address, privsep=1 empty-tree diagnostic in `classifyPVEError`, structured-fields-first error classification, removed time hack, and exported `ClassifyPVEError` wrapper. 6 additional items were intentionally deferred; see the Phase 2 deferred backlog below.

---

### Phase 2 — Userid + TTL Helpers + Roles Path

**Status**: ✅ COMPLETE — implemented and covered by unit tests.

**Tasks**:
- [x] Implement `userid.go` (buildUserID, randomSuffix 8-char base32 from crypto/rand, validateUserComponent, validateLengthBudget)
- [x] Implement `(*proxmoxRole).ttls(cfg)` fallback helper on `path_roles.go` (role value or config default) — there is NO `ttl.go`; capping is `framework.CalculateTTL`'s job
- [x] Implement `cappedMaxTTL(roleMax, sysMax time.Duration) time.Duration` on `path_roles.go` alongside `ttls()` — 4-case: (roleMax=0)→sysMax; (sysMax=0)→roleMax; (0,0)→0; (A,B)→min(A,B)
- [x] Implement `path_roles.go` (POST: ttl validation, userid budget, GetGroup ErrGroupNotFound check (body "does not exist", HTTP 500), per-group-path User.Modify check, GetPermissions realm check via ancestor-walk; GET/LIST/DELETE)
- [x] Unit tests: `userid_test.go` (buildUserID format, randomSuffix entropy, validateUserComponent rejects `:`, `/`, whitespace; validateLengthBudget >64 rejected)
- [x] Unit tests: `path_roles_test.go` (write validation, GetGroup ErrGroupNotFound (body "does not exist", HTTP 500), per-group-path User.Modify check (propagate=0 → reject), realm check, read/list/delete, `ttls()` fallback incl. both-unset; `cappedMaxTTL` 4-case: roleMax=0→sysMax, sysMax=0→roleMax, 0,0→0, A,B→min(A,B))

**Acceptance Criteria**:
- Roles CRUD operations work (unit tests pass)
- Userid validation (charset, length budget) works
- `ttls()` returns config defaults when role values are unset, and leaves 0 as 0 for `CalculateTTL` to resolve

**Architecture References**: `docs/ARCHITECTURE.md` Roles section, userid format and length budget, TTL Precedence section.

---

### Phase 2 — Deferred Review Backlog (from PR #3 Jester consensus)

These items were surfaced during the PR #3 Jester consensus review of Phase 1 and intentionally
deferred to a later phase. They are tracked here so they are not lost. Each item must be resolved
before or during the phase where its call site is introduced.

**Backlog status: ✅ ALL RESOLVED.** DR-1 through DR-4 were closed alongside the
phases that introduced their call sites; DR-5 (CLI collision documentation) and
DR-6 (verbatim probe fixtures) were the last two open items and are now complete
— see each item's Status and Verification below. No deferred review items remain.

---

#### DR-1 — `ErrUnauthenticated` (401) sentinel

**Status**: ✅ COMPLETE — `ErrUnauthenticated` is mapped from any HTTP 401
response before body-string classification, and issuance, renewal, and
revocation wrap it with an admin-token diagnostic while preserving `errors.Is`.

**What**: Add a new typed sentinel `ErrUnauthenticated` in `internal/pveapi/errors.go` and map
HTTP 401 to it in `classifyPVEError` (`client.go`). Currently a 401 response (e.g. from an
expired or revoked admin token) falls through to a generic `"HTTP 401 <endpoint>"` error.
"Engine config credentials are dead" is operationally distinct from Forbidden (403) or NotFound.
PVE returns 401 with an empty body when a token is expired or revoked (confirmed PVE 9.2.10).

**Verification**: Unit coverage exercises empty and non-empty 401 bodies;
the live authorization canary also verified that an expired-user token is
rejected with HTTP 401 on 2026-08-20.

**Where**: `internal/pveapi/errors.go` (new sentinel), `internal/pveapi/client.go`
(`classifyPVEError`), and any call site in `path_creds.go` / `secret_token.go` that calls the
PVE client and should surface a clear operator message.

**Acceptance Criterion**: `classifyPVEError` maps `status == 401` (any body, including empty) to
`ErrUnauthenticated`; at least one call site (e.g. issuance or renewal) wraps the error with a
human-readable message such as `"admin token unauthenticated — check config credentials"`.
Unit test: `classifyPVEError(401, []byte{})` returns `ErrUnauthenticated`.

---

#### DR-2 — Split `ErrNotFound` into `ErrUserNotFound` / `ErrGroupNotFound`

**Status**: ✅ COMPLETE — `ErrUserNotFound` and `ErrGroupNotFound` are distinct sentinels, client
classification maps the relevant PVE body strings to the correct sentinel, and call sites key
revocation idempotency specifically on `ErrUserNotFound`.

**What**: Earlier drafts used a single `ErrNotFound` sentinel overloaded across three body strings:
`"no such user"`, `"no such group"`, and `"does not exist"`. Different call sites require
different handling: revocation treats user-not-found as **success** (idempotent), renewal must
treat it as **failure**, and role-write surfaces group-not-found as `"group does not exist"`.
The coarse single sentinel makes those distinctions require an additional body-string scan at
the call site instead of a clean `errors.Is` check.

**Verification**: Unit coverage and the live lifecycle smoke test verify the
HTTP 500 body-string contract, including idempotent revoke handling for
`"no such user"`, on 2026-08-20.

**Where**: `internal/pveapi/errors.go` (new sentinels), `internal/pveapi/client.go`
(`classifyPVEError`), `secret_token.go` (`secretTokenRevoke`/`secretTokenRenew`), `wal.go`
(`walRollback`), `path_roles.go` (`GetGroup` error surface).

**Acceptance Criterion**: Distinct sentinels `ErrUserNotFound` and `ErrGroupNotFound` exist;
`classifyPVEError` maps body `"no such user"` → `ErrUserNotFound` and body `"no such group"` /
`"does not exist"` (group context) → `ErrGroupNotFound`; revocation idempotency keys on
`errors.Is(err, ErrUserNotFound)` specifically; renewal treats `ErrUserNotFound` as a hard
failure. Unit tests: table-driven body fixtures covering both sentinels.

---

#### DR-3 — `UpdateUserRequest` misuse guard (renewal safety)

**Status**: Complete — `UpdateUserRequest.Validate()` rejects unsafe `Enable=false` and
`Append=false` requests before any HTTP request is built; the mock client applies the same
validation before recording calls or invoking hooks.

**What**: `UpdateUserRequest{Enable bool, Append bool}` has dangerous zero values: `Enable=false`
sends `enable=0` (disabling the lease user in PVE); `Append=false` requests replacement-style
semantics that can wipe the user's `groups`, stripping all effective privileges. Renewal
has exactly one valid input combination: `Enable=true`, `Append=true`, with `Groups` re-sent.
Make invalid combinations unrepresentable or explicitly rejected before the wire call fires.

**Verification**: Renewal unit coverage and the live authorization canary
verify the safe `enable=1`, `append=1`, and group-preserving update shape.

**Where**: `internal/pveapi/types.go` or `client.go` (`UpdateUserRequest` definition / `UpdateUser`
call site in `secret_token.go`).

**Acceptance Criterion**: Either (a) a constructor `NewRenewalUpdate(userid string, expire int64,
group string) UpdateUserRequest` that always sets `Enable=true, Append=true` and is the only
route to renewal updates, or (b) a `Validate() error` on `UpdateUserRequest` that returns an
error for `!Enable || !Append`; a unit test proves that an expire-only / `Append=false` call is
rejected or structurally impossible before it reaches the wire.

---

#### DR-4 — Response body size cap (DoS hardening)

**Status**: ✅ COMPLETE — `internal/pveapi/client.go` reads at most 1 MiB + 1 byte and
returns typed `ErrResponseTooLarge` before attempting PVE error classification or JSON parsing.

**What**: `io.ReadAll(resp.Body)` in `client.go` `doRequest` (or equivalent) has no byte limit.
A misbehaving, misconfigured, or compromised PVE endpoint (or a MITM proxy) could return an
arbitrarily large body, causing unbounded memory allocation. PVE responses are small JSON
objects (< 1 KB in practice).

**Verification**: Boundary tests cover cap-1, cap, and cap+1 responses and
confirm oversized business-error bodies fail closed before classification.

**Where**: `internal/pveapi/client.go` — the response-body read in `doRequest` (or wherever
`resp.Body` is consumed before being passed to `classifyPVEError`).

**Acceptance Criterion**: The response body reader performs an N+1 bounded read
(`maxResponseBodyBytes+1`, cap ~1 MiB) so cap-1 and exactly-cap responses are accepted, while
cap+1 returns typed `ErrResponseTooLarge`. Do not use a naive
`io.LimitReader(resp.Body, maxBodyBytes)` that silently truncates without detecting overflow.
Unit tests cover the boundary sizes and confirm an oversized HTTP 500 DELETE body containing
`"no such user"` fails before business-error classification rather than returning
`ErrUserNotFound`.

---

#### DR-5 — `force` / `-force` CLI collision documentation

**Status**: ✅ COMPLETE — the collision is documented in all three places DR-5
names, and the guidance is locked in by unit tests rather than left as prose.

**Verification**:
- The `force` field `Description` in `pathConfig` (`path_config.go`) states that
  `force` is a DATA parameter, that `vault delete -force` is a CLI
  skip-confirmation flag which sends no force value and is therefore REJECTED,
  and gives both correct invocations (`vault delete <mount>/config force=true`
  for Vault CLI ≥ 1.11, and the `curl -X DELETE ".../config?force=true"` form).
- The guard's own rejection message (`configDelete`) now names the flag
  collision too — that message is what an operator who just typed `-force`
  actually sees, and previously gave no hint why the flag appeared ignored.
- `README.md` gains a "Deleting the Configuration" section with correct and
  WRONG invocations side by side, cross-referenced from the Vault API Paths
  table and from the provisioner-rotation section.
- The `Build & Run` section of this plan carries the same warning.
- `TestConfigDelete_WithoutForce_ExplainsCLIFlagCollision` and
  `TestConfigForceFieldDocumentsCLIFlagCollision` (`path_config_test.go`) assert
  the guard message and the field Description each mention `vault delete
  -force`, `force=true`, and the `?force=true` query form, so the documentation
  cannot silently regress.

**Rename evaluation (the optional half of the acceptance criterion)**: the field
KEEPS the name `force`. Renaming to `confirm_delete` would remove the collision
outright, but `force=true` is already the documented API surface in `README.md`,
`AGENTS.md`, `docs/ARCHITECTURE.md`, and operator runbooks, so a rename is a
breaking change to a published parameter in exchange for a confusion that three
lines of documentation and a self-explaining error message resolve. Trade-off
recorded here and in the `path_config.go` field comment; revisit only if a
future major version is already breaking the config API.

**What**: `DELETE <mount>/config` requires a `force=true` **data parameter**, but
`vault delete -force <path>` is a real Vault CLI **flag** (skip-confirmation prompt) that
transmits **no** `force` data param. An operator running `vault delete -force proxmox/config`
would hit the `"requires force=true"` error with no obvious explanation why the flag they just
passed was ignored.

**Why deferred**: Documentation / UX item. The DELETE config guard protects against orphaning
non-revocable leases — a hazard that does not exist until revocation is implemented in Phase 3.
Full operator-facing docs (README, field descriptions) are a Phase 6 deliverable.

**Where**: The `force` field `Description` in `pathConfig` (`path_config.go`), the `Build & Run`
section of this plan, and `README.md` (Phase 6).

**Acceptance Criterion**: The `force` field `Description` in `pathConfig` explicitly states that
`vault delete -force` is a CLI flag (skip-confirmation) and does **not** satisfy this parameter;
the correct invocations (`vault delete proxmox/config force=true` for Vault CLI ≥ 1.11, or
`curl -X DELETE ".../config?force=true"`) are documented in both the field description and
`README.md`. Optionally: evaluate renaming the field (e.g., `confirm_delete`) to avoid the
collision entirely — note the trade-off (non-standard name vs. less confusion).

---

#### DR-6 — Probe-fixture tests (upgrade unit tests to verbatim PVE bodies)

**Status**: ✅ COMPLETE — the fixture guard covers the captured PVE bodies used
by the engine's parsing and classification, with explicit occurrence counts for
ambiguous bodies and capture-specific anchors where labels share a line with
the body. The CLEAN 5-C fixture intentionally uses the synthetic value
documented in the redaction note in `docs/PVE_PROBES.md`.

**Verification**: `internal/pveapi/probe_fixtures_test.go` holds the fixture
bodies as raw string constants. `TestProbeFixturesRemainRawJSON` re-reads
`docs/PVE_PROBES.md` at test time, verifies each body appears on the expected
number of lines, and verifies every declared anchor shares a line with that
body (it also rejects literal line endings and invalid JSON). The CLEAN 5-C
value is synthetic as described by the redaction note in `docs/PVE_PROBES.md`;
the test protects the documented fixture shape without retaining the original
secret.

| Captured body | Replayed through | Asserts |
|---|---|---|
| Probe 0 version | `GetVersion` | version string `9.2.10` extracted |
| Probe 1 permissions | `GetPermissions` | full `PermissionTree` incl. propagate flags |
| Probe 1b `?path=` | `GetPermissions` + `HasPrivilege` | PVE echoes a TRAILING-SLASH key, so the scoped form does NOT answer the ancestor walk — the recorded reason the engine parses the unscoped dump |
| Probe 2 / 3 / 4 / 5 / 6b | `CreateUser`/`DeleteUser`/`GetUser`/`GetGroup`/`CreateToken` | `ErrConflict`, `ErrUserNotFound`, `ErrGroupNotFound` (6b asserts the match reads `errors.tokenid`, not `message`) |
| Probe 6 empty permissions | `GetPermissions` | empty tree parses, is not an error |
| Probe 6-fix C **and** D (403) | `GetPermissions` + `classifyPVEError` | `ErrForbidden` from the status before body matching, independent of JSON key order |
| Probe 6-fix A / CLEAN 5-B `{"data":{"/":{}}}` | `GetPermissions` + `HasPrivilege` | a present-but-empty path is NOT privilege possession |
| Probe CLEAN 5-C token create | `CreateToken` | the `value` field is returned as the secret (not `full-tokenid`, not the string-typed `info.privsep`) |
| `{"data":null}` (7-fix A/C, CLEAN 2-A/6-A) | `CreateUser`/`UpdateUser`/`DeleteUser` | mutating success is not a parse failure |
| GROUPADD, COMMENT, RENEWAL-PRESERVE | `GetUser` | groups/enable/expire/comment round-trip for the read-back assertions |
| Probe 7, 7-fix B, CLEAN 3-A/4-A/6-B (the empty-`groups` family) | `GetUser` | every capture where PVE reported NO membership decodes to an empty `Groups`, across varying key order and `tokens` (null vs populated). This is the PRECONDITION the issuance and renewal read-back assertions depend on, not those assertions themselves — they live in `path_creds.go`/`secret_token.go` and are covered separately in `path_creds_test.go`/`secret_token_test.go` against a mock returning an empty `Groups` |
| Probe 9 non-propagating | `HasPrivilege` | ancestor grant with propagate=0 → false |

Two captured bodies are deliberately NOT fixtured: `{"data":[]}` (Probe 6-fix E,
a `/cluster/resources` VM list) and the CLEAN 3-B group-member list, both from
endpoints the engine never calls — `GetGroup` discards its response body and
checks only the status/error contract.

**What**: The 9 verbatim-captured PVE response bodies in `docs/PVE_PROBES.md` (Probes 2–6b,
GROUPADD, RENEWAL-PRESERVE, etc.) should be replayed as test fixtures through
`classifyPVEError` and `GetPermissions`, rather than hand-authored approximations in `httptest`
handlers. This upgrades the test suite from "confirm my mental model of PVE" to "confirm actual
PVE wire output" — i.e. any drift between the plan's body-string assumptions and real PVE
output becomes a test failure rather than a silent pass.

**Why deferred**: Test-quality improvement. The unit tests in Phase 1 already use representative
bodies derived from the probes; this item replaces those approximations with verbatim
copy-pastes. Can be done any time after Phase 1 tests exist, but causes churn if done before
the error-classify surface stabilises (DR-1, DR-2 above may rename sentinels).

**Where**: `internal/pveapi/errors_test.go` and `internal/pveapi/client_test.go`; fixture bodies
sourced verbatim from `docs/PVE_PROBES.md`.

**Acceptance Criterion**: A table-driven test in `errors_test.go` replays each of the 9 captured
probe bodies verbatim (exact byte-for-byte JSON as recorded in `PVE_PROBES.md`) and asserts the
expected `classifyPVEError` result; a complementary fixture in `client_test.go` or
`permission_tree_test.go` replays the Probe 1 permissions response body through `GetPermissions`
and asserts the parsed `PermissionTree` matches the expected structure. No live PVE required.

---

### Phase 3 — Creds + Secret Token + WAL (Issuance)

**Status**: ✅ COMPLETE — implemented and covered by unit tests.

**Tasks**:
- [x] Implement `wal.go` (walTypeUser constant `"user"`, walUser struct with JSON/mapstructure keys `user_id` and `nonce`, walRollback decoding `map[string]interface{}`, GetUser ownership check requiring `comment == nonce`, DeleteUser ErrUserNotFound idempotency, accepted-risk header comment)
- [x] Implement `path_creds.go` (handleCredsRead full issuance: load role+config, `framework.CalculateTTL`, expire = lease end + 60s grace (refuse if unlimited per expire=0 policy), retry loop with per-attempt `nonce := walCommentPrefix + randomSuffix()`, `walID, err := PutWAL(..., walUser{UserID: userid, Nonce: nonce})` → CreateUser with `Comment: nonce` → on ErrConflict (body "already exists") `DeleteWAL(ctx, storage, walID)` + retry, read-back assert group membership and warn on comment/nonce mismatch, CreateToken with tokenid `lease` using the client-enforced `privsep=0`, on token-fail cleanup user+WAL, on DeleteWAL-fail cleanup user + return error, build Secret with internalData including group)
- [x] Implement `secret_token.go` (secretToken definition with Fields and non-nil Renew/Revoke callbacks; full implementation completed in Phase 4)
- [x] Wire WAL into backend: set `backend.WALRollback = b.walRollback`, `backend.WALRollbackMinAge = 5 * time.Minute`
- [x] Unit tests: `path_creds_test.go` (full issuance flow with mock client: success, ErrConflict retry with per-attempt WAL id, group read-back-failure injection, token-fail cleanup, DeleteWAL-fail → error+cleanup via failing-storage wrapper, collision exhaustion, expire grace applied; issuance REFUSED when effective TTL resolves to 0 (unlimited) per Locked Decision #9)
- [x] Unit tests: `wal_test.go` (walRollback: map payload decode using `user_id`+`nonce`, missing/empty `user_id` → error/retry, GetUser ErrUserNotFound (body "no such user", HTTP 500) → success, matching comment/nonce → DeleteUser success, comment mismatch/empty nonce → no delete, DeleteUser error → retry, unknown kind → error)

**Acceptance Criteria**:
- Creds issuance unit tests pass (including ErrConflict retry, group read-back-failure injection, token-fail cleanup, DeleteWAL-fail path)
- WAL rollback unit tests pass (nonce-gated ownership, idempotent user-not-found, unknown kind rejected)
- `DeleteWAL` is called with the id returned by `PutWAL` (compile-checked against the real signature)
- `CreateToken` explicitly sets `privsep=0` on the wire
- `CreateUser` sends `groups=<role.group>` and `expire=<leaseExpiry+grace>`
- Issued lease is renewable (`resp.Secret.Renewable == true`)

**Architecture References**: `docs/ARCHITECTURE.md` Implementation Notes — Service API Calls (Create ordering), Issuance ordering detail, userid collision retry and token creation conflict, privsep=0, WAL-Based Orphan Recovery section.

---

### Phase 4 — Renew/Revoke Callbacks

**Status**: ✅ COMPLETE — implemented and covered by unit tests.

**Tasks**:
- [x] Implement `secretTokenRenew` in `secret_token.go` (read pve_userid + group + nanosecond effective_max_ttl from internalData; `framework.CalculateTTL(b.System(), req.Secret.Increment, roleTTL, 0, storedMaxTTL, 0, req.Secret.IssueTime)`; pre-update GetUser refuses disabled users; UpdateUser re-sending expire+groups(from InternalData)+enable+append=1; read-back assert group preserved; update internalData["expire"]; return `&logical.Response{Secret: req.Secret}` with TTL/MaxTTL set)
- [x] Implement `secretTokenRevoke` in `secret_token.go` (read pve_userid, DeleteUser, ErrUserNotFound (body "no such user", HTTP 500) → nil, error → return error for Vault retry)
- [x] Unit tests: `secret_token_test.go` (renewal: capped from IssueTime not from now — an old lease near its max gets only the remainder; UpdateUser re-sends expire+groups+enable+append; group read from InternalData not role; disabled-user refusal; ErrUserNotFound(500+body) → fail; ErrUnauthenticated wraps with admin-token diagnostic; revocation: DeleteUser success, ErrUserNotFound(500+body) → success, error → retry)

**Acceptance Criteria**:
- Renew unit tests pass (total lease lifetime never exceeds `IssueTime + effective_max_ttl`, UpdateUser re-sends expire+groups+enable+append (full-replace); read-back confirms group preserved, ErrUserNotFound(500+body) fails renewal)
- Revoke unit tests pass (idempotent ErrUserNotFound (body "no such user", HTTP 500) → success, error → retry)

**Architecture References**: `docs/ARCHITECTURE.md` Lease Renewal section, Revocation section, idempotency (body "no such user" on HTTP 500 treated as success).

---

### Phase 5 — Full Unit Suite + Acceptance Tests

**Status**: ✅ COMPLETE (2026-08-20) — unit tests and operator-run acceptance
test code are present. Phase 5 local checks (`go build ./...`, `make test`,
and `make lint`) pass. The required live `make testacc` suite ran on the
operator's workstation against `pve-manager/9.2.10/43df2e01f27a1a19` on
2026-08-20 with all required tests green. Only the explicitly optional gates
listed below lacked prerequisites and skipped; any other skipped `TestAcc*` test
means Phase 5 is not complete. Live acceptance remains operator-run only and is
not run by CI.

**Tasks**:
- [x] Ensure Phase 5 local verification passes: `go build ./...`,
  `make test`, and `make lint` green
- [x] Implement `acceptance_test.go` with env gating (`VAULT_ACC=1`) and test
  scenarios:
  - [x] `TestAccLifecycle` (config→role→creds→`/version` auth smoke→renew→revoke→verify deleted by asserting "no such user" body (HTTP 500), not a 404)
  - [x] `TestAccAuthorizationContractCanary` (authoritative behavioral marker canary requires `PVE_BEHAVIORAL_PATH` + `PVE_BEHAVIORAL_MARKER`; optional ACL/negative probes are clearly labeled; expired-user token→401; renewal re-sends groups (full-replace))
  - [x] `TestAccRevocationIdempotencyAfterOutOfBandDelete` (issued user deleted out-of-band, revoke treats PVE body "no such user" HTTP 500 as success; live network-failure injection remains unit-test scope)
  - [x] `TestAccWALRollback` (manual WAL entry + rollback sweep)
  - [x] `TestAccConcurrentIssuance` (10 goroutines, verify collision retry works)
  - [x] `TestAccDeleteConfigGuard` (DELETE without force=true refused; with force=true succeeds)
- [x] Document required test env vars in `acceptance_test.go` comment header (PVE_ADDR, PVE_TOKEN_ID, PVE_TOKEN_SECRET, PVE_TEST_GROUP, plus behavioral marker requirements for the canary)
- [x] Run acceptance tests against an operator-provided disposable/dev PVE 9.2.10
  cluster: `make testacc` green for required tests on 2026-08-20 against
  `pve-manager/9.2.10/43df2e01f27a1a19`; only these optional gates may skip
  when their prerequisites are unset:
   - `TestAccInsufficientPrivileges` (`PVE_INSUFFICIENT_TOKEN_ID` and
     `PVE_INSUFFICIENT_TOKEN_SECRET`) — permitted skip; not run on 2026-08-20
   - `TestAccAuthorizationContractCanary/direct ACL anti-privilege-escalation`
     (`PVE_ACL_CANARY_PATH`, `PVE_ACL_CANARY_UNHELD_ROLE`, and
     `PVE_ACL_CANARY_TARGET_USER`) — permitted skip; not run on 2026-08-20
   - `TestAccAuthorizationContractCanary/negative authorization endpoint`
     (`PVE_NEGATIVE_AUTH_PATH`, optionally `PVE_NEGATIVE_AUTH_METHOD`) —
     permitted skip; not run on 2026-08-20
- [x] Keep live acceptance operator-run only; no GitHub Actions acceptance
  workflow is present, and normal PR CI remains unchanged

**Acceptance Criteria**:
- `make test` passes (all unit tests green)
- Required `make testacc` tests pass against live PVE; only the three optional
  gates listed above may skip when their prerequisites are not configured
- Required authorization contract canary passes (guards against PVE version
  changes)

**Architecture References**: `docs/ARCHITECTURE.md` Testing Strategy section, Acceptance Tests — authorization contract canary.

---

### Phase 6 — Build/Register/Smoke + CI + Docs

**Status**: ⚠️ PARTIALLY COMPLETE (2026-08-20) — `make build`, `make test`,
and `make lint` passed, and the full real Vault-server lifecycle smoke test
passed against the disposable `pve-manager/9.2.10/43df2e01f27a1a19` target.
Development-mode registration through `-dev-plugin-dir=./vault/plugins` and
enablement were verified. Production-style plugin catalog registration remains
unverified; see the trackable deferred gate below.
Therefore Phase 6 is not complete.

The operator-facing production verification procedure is maintained in
[`docs/PRODUCTION_VERIFICATION.md`](PRODUCTION_VERIFICATION.md). This
implementation plan is the canonical source for phase status and deferred
verification gates; do not create a second root-level backlog that restates
those gates.

The smoke test covered stored-config validation and secret redaction, role
creation, credential issuance, issued-token `/version` authentication,
renewal, revocation, PVE absence verification, the `force=true` delete guard,
forced deletion of stored config, and cached-client invalidation (a
post-delete credential request failed because config was gone, not because a
stale client was used).

The canonical `make testacc` command was also preflighted without printing
secrets. The exact missing variables were `PVE_BEHAVIORAL_PATH` and
`PVE_BEHAVIORAL_MARKER`; these gate the required authorization-contract canary
and are separate from the completed lifecycle smoke test. After those
variables were configured, the targeted canary was run on 2026-08-20 against
the configured disposable PVE target with:

```text
VAULT_ACC=1 go test -count=1 -v -timeout=30m ./... -run '^TestAccAuthorizationContractCanary$'
```

The test passed, including the positive behavioral-endpoint check and the
expired-user authentication and renewal checks. The optional direct ACL
anti-privilege-escalation and negative-authorization subtests skipped because
their separately documented optional variables were not configured. No PVE
changes were made outside the disposable target.

**Tasks**:
- [x] Build plugin: `make build` (output to `vault/plugins/`) — passed on
  2026-08-20
- [x] Manual smoke test (dev Vault server with `-dev-plugin-dir` → no manual
  register, enable, write config, write role, read creds, use token, renew,
  revoke, delete config with `force=true`) — passed on 2026-08-20 against
  `pve-manager/9.2.10/43df2e01f27a1a19`, including stored-config deletion and
  cached-client invalidation. The issued token authenticated successfully to
  `/version`; revocation was verified by the PVE `HTTP 500` body
  `"no such user"`. The config GET also confirmed `token_secret` is omitted.
  The acceptance canary preflight separately identified missing
  `PVE_BEHAVIORAL_PATH` and `PVE_BEHAVIORAL_MARKER`.
- [x] Run the required authorization-contract canary after configuring
  `PVE_BEHAVIORAL_PATH` and `PVE_BEHAVIORAL_MARKER` — targeted command passed
  on 2026-08-20 against the configured disposable PVE target. The positive
  behavioral endpoint passed; the optional direct ACL and negative-authorization
  subtests skipped because their optional variables were unset.
- [x] Update `README.md` with: overview, build/install instructions,
  configuration example, role example, usage example, development/testing notes
- [x] CI config (GitHub Actions or equivalent): normal PR CI runs build, unit
  tests, and lint only; live acceptance is operator-run only and never run by CI
- [x] Verify `AGENTS.md` and `docs/ARCHITECTURE.md` are accurate and up-to-date
  for recorded Phase 5/Phase 6 status

**Acceptance Criteria**:
- Clean build (`make build` succeeds)
- Plugin auto-registers and enables through `-dev-plugin-dir` (verified)
- Production catalog registration is tracked by the unchecked production
  adoption gate below and is not claimed as complete
- Full issue→use→renew→revoke smoke test passes through a real `vault server`
  plus registered plugin binary with required live PVE configuration
- Stored config can be force-deleted and the cached PVE client is invalidated
  (post-delete credential access fails because config is absent)
- CI runs on PR: fmt/lint/test green
- Live acceptance required tests have a recorded operator green result from
  2026-08-20 against `pve-manager/9.2.10/43df2e01f27a1a19`; only the three
  optional gates listed above may skip when their prerequisites are not configured
- `README.md` has build, config, and usage examples

**Explicitly skipped optional canaries on 2026-08-20** (their prerequisites
were unset; these are not failures and are not complete):

- `TestAccInsufficientPrivileges` — `PVE_INSUFFICIENT_TOKEN_ID` /
  `PVE_INSUFFICIENT_TOKEN_SECRET`
- Direct ACL anti-privilege-escalation canary — `PVE_ACL_CANARY_PATH`,
  `PVE_ACL_CANARY_UNHELD_ROLE`, and `PVE_ACL_CANARY_TARGET_USER`
- Negative authorization endpoint canary — `PVE_NEGATIVE_AUTH_PATH` (and
  optional method override)

The required positive behavioral authorization canary passed, including the
group-role-gated endpoint, expired-user HTTP 401 check, and renewal
group-preservation check. Omitted-`append` semantics remain unresolved; the
engine therefore continues to send explicit `append=1` with `expire` +
`groups` + `enable` and read back membership.

**Architecture References**: `docs/ARCHITECTURE.md` Root Rotation section (manual operation), Build & Run commands above.

---

## Deferred / Future Work

### Production adoption gates

- [ ] Build one approved artifact, distribute it to every Vault node, and
  verify identical digest, executable permissions, ownership, and path.
- [ ] Register the plugin in the production catalog with the verified digest;
  verify catalog and mount persistence across restart.
- [ ] Verify standby-to-active forwarding before any PVE mutation, controlled
  failover, and issue/renew/revoke through the cluster address after failover.
- [ ] Verify restart recovery for leases, WAL cleanup, PVE users/tokens,
  catalog state, mount state, and audit evidence across nodes.
- [ ] On an approved disposable target, inject a failure between WAL creation
  and cleanup, then record rollback-manager evidence that the nonce-matched
  orphan `vault-*` PVE user was deleted. Do not make production adoption
  depend on this destructive failure-injection test.

### Password Credential Support (gated future feature)

Password credentials are deliberately not implemented; the engine currently issues
only PVE API tokens. Do not make token-only production adoption depend on this work,
add password fields, or alter the token lifecycle as part of the release gates.
Complete the following tasks in order. **P0 is pending, and all implementation tasks
are gated until its live PVE 9.2.10 evidence is recorded.**

- [ ] **P0 — Live PVE password behavior probe (pre-implementation)**
  - **Files/scope**: `docs/PVE_PROBES.md`, disposable PVE 9.2.10 target, probe
    notes/scripts as appropriate; no application code.
  - **Dependencies**: operator-provided disposable PVE 9.2.10 cluster and
    credentials; none of the implementation tasks may start before this task is
    complete.
  - **Checklist**: verify password user creation and authentication; determine
    password rotation/update behavior; verify expiry, disablement, deletion, and
    interaction with token credentials and the user-level `expire` backstop. Exercise
    the exact engine renewal shape `expire + groups + enable + append=1`, read the
    user back, and authenticate with the original password afterward. Probe which
    realm types accept password credentials (including the configured/default `pve`
    realm and non-password realms), recording the exact HTTP status and redacted body
    for every failure. Probe the privileges required to create/set a password,
    recording the exact ACL path, privilege, and propagation flag; compare them with
    the existing `/access/groups` and `/access/realm/<realm>` checks. Record PVE
    password minimum and maximum constraints needed by the generator. Determine and
    record the exact password API call shape: whether the password is supplied on
    `POST /access/users` or set by a separate password-setting call, including request
    ordering and response/error behavior. Capture exact status/body behavior
    throughout and redact all password values from evidence.
  - **Acceptance**: reproducible probe evidence is recorded in `docs/PVE_PROBES.md`
    with no password values; unresolved behavior is explicitly listed; implementation
    gate is opened only after review.

- [ ] **P1 — Contract and documentation finalization (pre-implementation)**
  - **Files/scope**: `docs/IMPLEMENTATION_PLAN.md`, `docs/ARCHITECTURE.md`,
    `README.md`, and any password-specific operator documentation.
  - **Dependencies**: P0 evidence and review.
  - **Checklist**: reconcile the confirmed `mode` contract with probe findings;
    document exact response fields, separate secret type, no-token behavior,
    one-time password handling, compatibility, and error paths; define migration
    behavior for existing token roles/leases. Lock password-generator ownership
    (engine versus PVE), length, charset, `crypto/rand` entropy requirements, and
    PVE minimum/maximum constraints from P0 before P4 can start. Define redaction
    requirements for responses, errors, logs, WAL, and `InternalData`. Lock the
    password API call shape and compensation ordering before P4. If the password is
    supplied on `POST /access/users`, explicitly treat the credential as live before
    group read-back and WAL cleanup complete. Any post-create or read-back failure
    MUST compensate by revoking/deleting the live credential; if deletion fails,
    retain the nonce-gated WAL entry for rollback. If separate post-create password
    setting is required, apply the same `DeleteUser` compensation and conditional WAL
    cleanup rules. Explicitly decide and lock the password-mode comment read-back
    policy: retain the token-mode soft warning, or make a nonce mismatch fatal and
    delete the user before failing issuance. Treat renewal as design intent unless
    P0 proves the original password still authenticates.
  - **Acceptance**: the plan, architecture, README, and operator guidance agree;
    no document claims unsupported PVE behavior or exposes a secret.

- [ ] **P2 — Role schema and validation**
  - **Files/scope**: `path_config.go`, `path_roles.go`, privilege documentation and
    tests if P0 identifies new requirements, role storage/schema documentation, and
    relevant compatibility tests.
  - **Dependencies**: P1; preserve existing token role decoding and validation.
  - **Checklist**: add `mode` validation for `token`/`password`; default omission to
    `token` on both write and read, and require `getRole()` to normalize decoded
    `mode == ""` to `token` before returning the role; add tests for legacy stored roles with absent or
    empty mode; persist/read the field without changing existing role or lease data;
    reject unsupported values clearly; ensure role responses and help text are exact.
    Add password-mode realm applicability validation at role-write time, based on P0's
    exact status/body evidence, while preserving token-mode realm behavior. If P0
    finds password-specific privileges, update the config precheck in
    `path_config.go`, role precheck in `path_roles.go`, ACL/operator privilege docs,
    and their tests; retain the existing token privilege behavior unchanged.
  - **Acceptance**: old roles round-trip as token roles; invalid modes fail; new
    password roles round-trip; token role tests remain green.

- [ ] **P3 — Separate password secret type**
  - **Files/scope**: new password secret implementation (likely
    `secret_password.go`), `backend.go`, and secret unit tests.
  - **Dependencies**: P1 and P2; use only the confirmed PVE behavior.
  - **Checklist**: define a distinct Vault secret type returning exactly `user_id`
    and `password`; implement only the generator contract locked in P1: explicit
    ownership, length, charset, `crypto/rand` entropy, and PVE min/max compliance;
    keep password out of WAL, InternalData, logs, and error text, with redaction tests;
    register callbacks without changing the token secret type. P3 must not invent or
    silently choose any generator parameter left unresolved by P0/P1.
  - **Acceptance**: schema has no extra response fields; secret redaction tests pass;
    token secret registration and existing leases remain unchanged.

- [ ] **P4 — Password issuance and compensation**
  - **Files/scope**: `path_creds.go` or password issuance helper, `wal.go`,
    `internal/pveapi/*`, and issuance/compensation tests.
  - **Dependencies**: P0–P3; blocked until P0 evidence and the P1/P3 password
    generator and redaction gates are locked.
  - **Checklist**: branch on role mode; create the PVE user with the confirmed
    password request shape and existing expiry/group safeguards; never create an API
    token in password mode; return the password once; preserve nonce-gated WAL
    ownership and collision handling; compensate every post-WAL failure without
    persisting or logging the password. Apply the P1-locked password comment
    read-back policy explicitly: either retain the token-mode soft warning, or make
    a nonce mismatch fatal, delete the user, and fail issuance. Do not inherit this
    behavior implicitly from token mode. If same-call creation succeeds but group
    read-back fails (including a read-back error), call `DeleteUser`; delete the WAL
    only when that deletion returns nil or `ErrUserNotFound`, and retain the WAL and
    return the cleanup error when deletion fails transiently.
  - **Acceptance**: password issuance returns exactly the contract fields; mock
    assertions prove no token call; collision, tokenless failure, group read-back
    failure, conditional WAL cleanup, and user cleanup paths are covered; the
    P1-selected comment mismatch policy is explicit and enforced; password values
    never appear in logs, errors, WAL, `InternalData`, or Vault storage; token
    issuance is behaviorally unchanged.

- [ ] **P5 — Password renewal and revocation**
  - **Files/scope**: password secret callbacks, `secret_password.go`, and lifecycle
    tests; update architecture references if probe results require it.
  - **Dependencies**: P0–P4.
  - **Checklist**: if P0 proves the exact renewal PUT preserves authentication,
    renewal extends expiry only using the existing TTL rules; otherwise stop and
    revise the lifecycle design before implementation. Do not rotate or return a
    password unless P0/P1 explicitly change that contract. Revoke the PVE user
    idempotently; define behavior for disabled users, expired users, and out-of-band
    password changes from probe data.
  - **Acceptance**: conditional on P0 evidence, renewal never invokes password
    rotation and never returns a password; revocation removes the user and is
    retry-safe; token renew/revoke tests remain green.

- [ ] **P6 — WAL and lifecycle test coverage**
  - **Files/scope**: `wal_test.go`, `path_creds_test.go`, `secret_password_test.go`,
    `acceptance_test.go` (gated `TestAcc*` additions), and testing documentation.
  - **Dependencies**: P0–P5.
  - **Checklist**: add unit coverage for secret non-persistence, nonce ownership,
    crash recovery, compensation, renewal, revocation, compatibility, and log/error
    redaction; mock password-mode group read-back failure after same-call creation
    and assert `DeleteUser`; assert that a transient `DeleteUser` failure retains
    the WAL, while nil or `ErrUserNotFound` permits WAL deletion. Test the
    P1-selected password comment mismatch policy, including any required delete
    and WAL behavior. Assert that password values are absent from logs, errors,
    WAL, `InternalData`, and stored Vault data. Add opt-in live coverage for
    authentication, expiry, disablement, deletion, and confirmed token interaction.
  - **Acceptance**: unit tests pass without live PVE; password acceptance tests are
    `VAULT_ACC=1` gated, require explicit P0 evidence/prerequisites, and never print
    secrets; existing acceptance tests remain unchanged and green.

- [ ] **P7 — Operator documentation and security review**
  - **Files/scope**: `README.md`, `docs/ARCHITECTURE.md`, `AGENTS.md`,
    `docs/PRODUCTION_VERIFICATION.md`, `docs/IMPLEMENTATION_PLAN.md`, and audit/
    security review notes. Include `docs/ARCHITECTURE.md` and `AGENTS.md` in the
    review when password creation changes existing orphan-handling assumptions.
  - **Dependencies**: P0–P6.
  - **Checklist**: document configuration, response handling, password lifetime,
    disablement/revocation expectations, audit evidence, privilege implications,
    compatibility, and recovery procedures; review logs, WAL, InternalData, error
    paths, and operator workflows for secret exposure. Document the live-credential
    orphan windows separately: for a nonce-matched orphan, from same-call password
    creation through `WALRollbackMinAge` plus rollback retry time; for an empty- or
    nonce-mismatched orphan, potentially through the full PVE `expire` lifetime or
    until manual cleanup, because `walRollback` intentionally drops that WAL entry
    without deleting a foreign/mismatched user. Include the PVE `expire` backstop as
    mitigation for both cases. Reconcile the resulting orphan-handling assumptions
    in `docs/ARCHITECTURE.md` and `AGENTS.md` as appropriate.
  - **Acceptance**: security review is recorded; operator docs match the shipped
    behavior and probe evidence; no token-only production gate is weakened.

---

## Open Assumptions

Minor details for the implementer to confirm or decide:

1. **`hashicorp/vault/sdk` version**: Do NOT hand-write a version into `go.mod` — run `go get -u github.com/hashicorp/vault/sdk github.com/hashicorp/go-hclog && go mod tidy` and take whatever is current. (The SDK signatures this plan depends on — `PutWAL`/`DeleteWAL`, `CalculateTTL`, `Secret.Response` — were verified against v0.9.1 and are long-stable, but re-check them against the resolved version before writing the issuance path.)
2. **Plugin serve mode**: Use `plugin.ServeMultiplex` for multiplexed gRPC (recommended for newer Vault versions) or `plugin.Serve` for simpler single-protocol serve. With `ServeMultiplex`, do NOT set `TLSProviderFunc`. Confirm Vault version compatibility.
3. **`golangci-lint` availability**: Use the pinned v2 version via `go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2 run` (the `/v2/` module path is required for v2). The Makefile `lint` target (via `GOLANGCI_LINT_VERSION`) and CI (`.github/workflows/ci.yml`, SHA-pinned `golangci-lint-action`) both pin `v2.12.2` so local and CI agree. **Pin floor reasoning — two paths, same constraint:** (a) *CI action path*: the action downloads a pre-built binary; that binary must have been built with Go >= this module's language version, so the pinned release must satisfy that floor. (b) *`go run`/Makefile path*: `go run` compiles golangci-lint at *golangci-lint's own* go.mod language version (NOT this module's); older releases (e.g. v2.1.6, v2.5.0) had pre-1.25 go directives and REFUSED this module even on Go 1.25.7. v2.12.2's go.mod requires `go >= 1.25.0`, so `go run` selects a >=1.25 toolchain and the resulting binary clears golangci-lint's build-version guard. The pin cannot be lowered below a golangci-lint release whose own go directive is >= this module's Go language version.
4. **Crockford base32 alphabet**: Confirm charset `0123456789abcdefghjkmnpqrstvwxyz` (Crockford, lowercase, no padding) for random suffix. Implementation may use a library or manual mapping.
5. **Acceptance test PVE cluster**: Operator must pre-create the test group (`PVE_TEST_GROUP`) and bind it to a test role (e.g., PVEVMAdmin at `/vms/test`) before running acceptance tests. Document this prerequisite in `acceptance_test.go` and `README.md`.
6. **WALRollbackMinAge tuning**: 5 minutes is a safe default. May tune lower (e.g., 1 minute) if issuance latency is predictably low, or higher (e.g., 10 minutes) if cluster lock contention causes slower provisioning.
7. **HTTP client timeout**: Choose a reasonable timeout for PVE API calls (e.g., 30 seconds). May make configurable in future.
8. **`expire` grace**: 60 seconds past the lease end is the starting value for the clock-skew buffer between the Vault host and the PVE cluster. Tune if the two are known to be tightly NTP-synced (lower) or not synced at all (higher).
9. **`vault delete ... force=true`**: confirm the installed Vault CLI forwards K=V pairs on DELETE as query parameters (≥ 1.11). Otherwise document the curl form as the supported path.

These are low-risk decisions that don't alter the core design.

---

**End of Implementation Plan**
