// Package proxmox — roles path: <mount>/roles/:name (POST/GET/LIST/DELETE).
//
// POST: Validate TTLs, realm charset, userid length budget, group existence
//       via GetGroup (ErrGroupNotFound from HTTP 500 + body "does not exist"),
//       Realm.AllocateUser via GetPermissions ancestor-walk, and per-group-path
//       User.Modify check to detect --propagate 0 misconfiguration.
//
// GET:    Return role fields.
// LIST:   List role names under roles/.
// DELETE: Delete role entry (does NOT revoke outstanding leases — already-issued
//         credentials remain valid until their lease expires or is explicitly
//         revoked; renew/revoke rely on pve_userid in lease InternalData).
//
// TTL helpers:
//   - (*proxmoxRole).ttls(cfg) — fallback chain for issuance/renewal TTL inputs.
//   - cappedMaxTTL(roleMax, sysMax) — 4-case min helper (treats 0 as "unset").
//
// See docs/ARCHITECTURE.md Roles section and docs/IMPLEMENTATION_PLAN.md for
// the full spec.
package proxmox

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	pveapi "github.com/hazmei/vault-plugin-secrets-proxmox/internal/pveapi"
)

// proxmoxRole is the config stored at storage key "roles/<name>".
//
// TTL fields (TTL, MaxTTL) are stored in seconds (int). A value of 0 means
// "unset" — fall back to config.default_ttl / config.default_max_ttl, then to
// Vault's system defaults via framework.CalculateTTL. Callers use ttls(cfg) to
// get the fallback-resolved time.Duration pair and pass them to CalculateTTL.
type proxmoxRole struct {
	// Group is the name of the operator-pre-created PVE group that synthetic
	// users are added to. The group must already exist and be bound by a cluster
	// admin to the desired ACL roles.
	Group string `json:"group"`

	// UserPrefix is the prefix for the synthetic userid, e.g. "vault".
	// Validated against the Proxmox userid charset (no whitespace, ':', '/', '@', '!').
	UserPrefix string `json:"user_prefix"`

	// Realm is the PVE authentication realm for synthetic users (default "pve").
	Realm string `json:"realm"`

	// TTL is the lease TTL in seconds (0 = unset; falls back to config or system default).
	TTL int `json:"ttl"`

	// MaxTTL is the maximum lease TTL in seconds (0 = unset; falls back to config or system max).
	MaxTTL int `json:"max_ttl"`
}

// ttls returns the effective (ttl, maxTTL) time.Duration pair for this role,
// applying the fallback chain: role value → config default → 0 (for CalculateTTL
// to resolve against system defaults).
//
// CRITICAL: config.default_ttl is a FALLBACK, NOT a cap. A naive min() would
// collapse TTL to 0 when role values are unset. This function only sets ttl/maxTTL
// to the config default when the role value is 0 (unset). The actual capping
// against system/mount limits is framework.CalculateTTL's responsibility.
func (r *proxmoxRole) ttls(cfg *proxmoxConfig) (ttl, maxTTL time.Duration) {
	ttl = time.Duration(r.TTL) * time.Second
	if ttl == 0 {
		ttl = time.Duration(cfg.DefaultTTL) * time.Second
	}
	maxTTL = time.Duration(r.MaxTTL) * time.Second
	if maxTTL == 0 {
		maxTTL = time.Duration(cfg.DefaultMaxTTL) * time.Second
	}
	return
}

// cappedMaxTTL returns the effective max TTL, treating 0 as "unset" (no cap
// from that source) rather than "zero seconds":
//
//   - (0, sysMax) → sysMax   (role unset, use system max)
//   - (roleMax, 0) → roleMax  (system max unset, use role max)
//   - (0, 0)       → 0        (both unset — unlimited; issuance refuses this)
//   - (A, B)       → min(A,B) (both set — use stricter limit)
//
// Home file: path_roles.go (TTL helper, lives alongside ttls()).
// Used by path_creds.go to compute effective_max_ttl stored in lease InternalData.
func cappedMaxTTL(roleMax, sysMax time.Duration) time.Duration {
	switch {
	case roleMax == 0:
		return sysMax
	case sysMax == 0:
		return roleMax
	default:
		if roleMax < sysMax {
			return roleMax
		}
		return sysMax
	}
}

// getRole loads and decodes the role entry from storage.
// Returns (nil, nil) when no role has been written for this name.
func getRole(ctx context.Context, storage logical.Storage, name string) (*proxmoxRole, error) {
	entry, err := storage.Get(ctx, "roles/"+name)
	if err != nil {
		return nil, fmt.Errorf("proxmox: read role %q from storage: %w", name, err)
	}
	if entry == nil {
		return nil, nil
	}

	var role proxmoxRole
	if err := entry.DecodeJSON(&role); err != nil {
		return nil, fmt.Errorf("proxmox: decode role %q: %w", name, err)
	}
	return &role, nil
}

// pathRoles returns the framework.Path slice for <mount>/roles/:name and the
// listing endpoint <mount>/roles/.
func pathRoles(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "roles/" + framework.GenericNameRegex("name"),
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "proxmox",
				OperationSuffix: "role",
			},
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Role name. Used as part of the synthetic PVE userid.",
					Required:    true,
				},
				"group": {
					Type:        framework.TypeString,
					Description: "Name of the operator-pre-created PVE group that synthetic users are added to. Must exist on the Proxmox cluster before the role is created.",
					Required:    true,
				},
				"user_prefix": {
					Type:        framework.TypeString,
					Description: "Prefix for the synthetic PVE userid (e.g. 'vault'). May contain alphanumeric and '-', '_', '.' characters — not whitespace, ':', '/', '@', or '!'.",
					Default:     "vault",
				},
				"realm": {
					Type:        framework.TypeString,
					Description: "PVE authentication realm for synthetic users (default 'pve'). Must match ^[A-Za-z][A-Za-z0-9.\\-_]+$.",
					Default:     "pve",
				},
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Lease TTL in seconds (0 = unset; falls back to config.default_ttl, then Vault system default).",
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Maximum lease TTL in seconds (0 = unset; falls back to config.default_max_ttl, then Vault system max).",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{Callback: b.roleWrite},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.roleWrite},
				logical.ReadOperation:   &framework.PathOperation{Callback: b.roleRead},
				logical.DeleteOperation: &framework.PathOperation{Callback: b.roleDelete},
			},
			ExistenceCheck:  b.roleExistenceCheck,
			HelpSynopsis:    "Manage Proxmox VE dynamic secrets roles.",
			HelpDescription: "POST: Create or update a role specifying the PVE group, user prefix, realm, and TTL parameters. GET: Read a role. DELETE: Remove a role (does not revoke outstanding leases).",
		},
		{
			// List endpoint: GET/LIST <mount>/roles
			Pattern: "roles/?",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "proxmox",
				OperationSuffix: "roles",
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{Callback: b.roleList},
			},
			HelpSynopsis:    "List Proxmox VE dynamic secrets roles.",
			HelpDescription: "Returns the list of role names.",
		},
	}
}

// roleExistenceCheck reports whether a role entry exists.
// Required by the framework when CreateOperation is registered on the path.
func (b *backend) roleExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	name := d.Get("name").(string)
	role, err := getRole(ctx, req.Storage, name)
	if err != nil {
		return false, err
	}
	return role != nil, nil
}

// roleWrite handles POST/PUT to <mount>/roles/:name.
//
// Steps:
//  1. Validate TTL ordering (ttl <= max_ttl when both set).
//  2. Default and validate realm.
//  3. Validate user_prefix and role name charset.
//  4. Validate userid length budget.
//  5. Load config and build PVE client.
//  6. GetGroup: verify group exists (ErrGroupNotFound from HTTP 500 + "does not exist").
//  7. GetPermissions: confirm Realm.AllocateUser at /access/realm/<realm>.
//  7b. GetPermissions: confirm User.Modify is effective at per-group path
//     /access/groups/<group> (catches --propagate 0 misconfiguration).
//  8. Store role to roles/<name>.
func (b *backend) roleWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	group := d.Get("group").(string)
	userPrefix := d.Get("user_prefix").(string)
	realm := d.Get("realm").(string)
	ttl := d.Get("ttl").(int)
	maxTTL := d.Get("max_ttl").(int)

	// Validate required fields.
	if group == "" {
		return logical.ErrorResponse("group is required"), nil
	}

	// Step 1: Validate TTL ordering.
	if ttl < 0 {
		return logical.ErrorResponse("ttl cannot be negative"), nil
	}
	if maxTTL < 0 {
		return logical.ErrorResponse("max_ttl cannot be negative"), nil
	}
	if ttl > 0 && maxTTL > 0 && ttl > maxTTL {
		return logical.ErrorResponse("ttl (%d) must not exceed max_ttl (%d)", ttl, maxTTL), nil
	}

	// Step 2: Default and validate realm.
	if realm == "" {
		realm = "pve"
	}
	if err := validateRealmComponent(realm); err != nil {
		return logical.ErrorResponse("invalid realm: %s", err), nil
	}

	// Default user_prefix if not provided.
	if userPrefix == "" {
		userPrefix = "vault"
	}

	// Step 3: Validate user_prefix and role name charset.
	if err := validateUserComponent(userPrefix); err != nil {
		return logical.ErrorResponse("invalid user_prefix: %s", err), nil
	}
	if err := validateUserComponent(name); err != nil {
		return logical.ErrorResponse("invalid role name: %s", err), nil
	}

	// Step 4: Validate userid length budget.
	if err := validateLengthBudget(userPrefix, name, realm); err != nil {
		return logical.ErrorResponse("%s", err), nil
	}

	// Step 5: Load config and build PVE client.
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("proxmox: load config: %w", err)
	}
	if cfg == nil {
		return logical.ErrorResponse("no config found; write config to <mount>/config first"), nil
	}

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("proxmox: get PVE client: %w", err)
	}

	// Step 6: Verify group exists on the Proxmox cluster.
	// GetGroup returns ErrGroupNotFound (HTTP 500 + body "does not exist") for
	// missing groups. PVE never returns 404. DR-2 uses ErrGroupNotFound specifically.
	if err := client.GetGroup(ctx, group); err != nil {
		if errors.Is(err, pveapi.ErrGroupNotFound) {
			return logical.ErrorResponse("group %q does not exist on Proxmox cluster; create it out-of-band before defining this role", group), nil
		}
		if errors.Is(err, pveapi.ErrForbidden) {
			return logical.ErrorResponse("PVE returned 403 checking group %q — admin token may lack Sys.Audit at /access/groups; %s", group, err), nil
		}
		return nil, fmt.Errorf("proxmox: GetGroup %q: %w", group, err)
	}

	// Step 7: Confirm Realm.AllocateUser at /access/realm/<realm> via permissions ancestor-walk.
	tree, err := client.GetPermissions(ctx)
	if err != nil {
		if errors.Is(err, pveapi.ErrForbidden) {
			return logical.ErrorResponse("PVE returned 403 on GET /access/permissions during role-write — check admin token privileges"), nil
		}
		return nil, fmt.Errorf("proxmox: GetPermissions: %w", err)
	}

	realmPath := "/access/realm/" + realm
	if !tree.HasPrivilege(realmPath, "Realm.AllocateUser") {
		return logical.ErrorResponse(
			"admin token lacks Realm.AllocateUser at %s (or an ancestor with propagate=1); "+
				"grant: pveum acl modify %s --user <admin> --role <role>",
			realmPath, realmPath,
		), nil
	}

	// Step 7b: Per-group-path User.Modify check.
	// PVE checks User.Modify at the per-group path /access/groups/<group> for user
	// creation. A --propagate 0 grant at /access/groups (the parent) passes the
	// parent-level check but fails at creation time. HasPrivilege at the per-group
	// path catches this at role-write time instead.
	// (Confirmed PVE 9.2.10, PVE_PROBES.md Probe 9: propagate flag :0 vs :1 is
	// visible in the permissions tree.)
	perGroupPath := "/access/groups/" + group
	if !tree.HasPrivilege(perGroupPath, "User.Modify") {
		return logical.ErrorResponse(
			"admin token lacks User.Modify at %s; this usually means the grant at /access/groups uses --propagate 0 "+
				"(creation checks the per-group path; renewal/revocation check the parent /access/groups); "+
				"fix: pveum acl modify /access/groups --user <admin> --role <role> --propagate 1",
			perGroupPath,
		), nil
	}

	// Step 8: Store role.
	role := &proxmoxRole{
		Group:      group,
		UserPrefix: userPrefix,
		Realm:      realm,
		TTL:        ttl,
		MaxTTL:     maxTTL,
	}

	entry, err := logical.StorageEntryJSON("roles/"+name, role)
	if err != nil {
		return nil, fmt.Errorf("proxmox: marshal role %q for storage: %w", name, err)
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, fmt.Errorf("proxmox: store role %q: %w", name, err)
	}

	return nil, nil
}

// roleRead handles GET to <mount>/roles/:name.
func (b *backend) roleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	role, err := getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"group":       role.Group,
			"user_prefix": role.UserPrefix,
			"realm":       role.Realm,
			"ttl":         role.TTL,
			"max_ttl":     role.MaxTTL,
		},
	}, nil
}

// roleList handles LIST to <mount>/roles.
func (b *backend) roleList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	keys, err := req.Storage.List(ctx, "roles/")
	if err != nil {
		return nil, fmt.Errorf("proxmox: list roles: %w", err)
	}
	return logical.ListResponse(keys), nil
}

// roleDelete handles DELETE to <mount>/roles/:name.
//
// Deleting a role does NOT revoke its outstanding leases — already-issued
// credentials remain valid until their lease expires or is explicitly revoked.
// Renew and revoke operations rely on pve_userid stored in lease InternalData,
// not on the role still existing.
func (b *backend) roleDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	if err := req.Storage.Delete(ctx, "roles/"+name); err != nil {
		return nil, fmt.Errorf("proxmox: delete role %q: %w", name, err)
	}

	return nil, nil
}
