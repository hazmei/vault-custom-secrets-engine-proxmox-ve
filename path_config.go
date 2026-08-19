// Package proxmox — config path: <mount>/config (POST/GET/DELETE).
//
// POST:   Validate TTL ordering, build PVE client, check GetVersion +
//
//	GetPermissions (User.Modify + Sys.Audit at /access/groups via
//	ancestor-walk), store seal-wrapped at key "config".
//
// GET:    Return all fields except token_secret.
// DELETE: Require force=true query parameter.
//
// See docs/IMPLEMENTATION_PLAN.md §path_config.go and docs/ARCHITECTURE.md
// Configuration section for the full spec and permission-tree ancestor walk.
package proxmox

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	pveapi "github.com/hazmei/vault-plugin-secrets-proxmox/internal/pveapi"
)

// configExistenceCheck reports whether a config entry already exists.
// Required by the framework when CreateOperation is registered on the path —
// the framework uses ExistenceCheck to distinguish create from update.
func (b *backend) configExistenceCheck(ctx context.Context, req *logical.Request, _ *framework.FieldData) (bool, error) {
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return false, err
	}
	return cfg != nil, nil
}

// pathConfig returns the framework.Path for <mount>/config.
func pathConfig(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "proxmox",
		},
		Fields: map[string]*framework.FieldSchema{
			"address": {
				Type:        framework.TypeString,
				Description: "Proxmox VE API base URL (e.g. https://pve.example.com:8006). Must include scheme.",
				Required:    true,
			},
			"token_id": {
				Type:        framework.TypeString,
				Description: "Proxmox API token ID in <user>@<realm>!<tokenid> format.",
				Required:    true,
			},
			"token_secret": {
				Type:        framework.TypeString,
				Description: "Proxmox API token secret (UUID). Write-only — never returned on GET.",
				Required:    true,
			},
			"tls_skip_verify": {
				Type:        framework.TypeBool,
				Description: "Skip TLS certificate verification. Prefer ca_cert for self-signed certs.",
				Default:     false,
			},
			"ca_cert": {
				Type:        framework.TypeString,
				Description: "PEM-encoded CA certificate bundle for self-signed Proxmox TLS certificates.",
			},
			"default_ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Default lease TTL in seconds. Fallback when role.ttl is unset. 0 = use Vault system default.",
			},
			"default_max_ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Default maximum lease TTL in seconds. Fallback when role.max_ttl is unset. 0 = use Vault system max.",
			},
			// force is declared as a TypeBool so Vault CLI can pass it as
			// a query parameter on DELETE: vault delete proxmox/config force=true
			"force": {
				Type:        framework.TypeBool,
				Description: "Required on DELETE to confirm deletion of config (force=true).",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: b.configWrite},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.configWrite},
			logical.ReadOperation:   &framework.PathOperation{Callback: b.configRead},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.configDelete},
		},
		ExistenceCheck:  b.configExistenceCheck,
		HelpSynopsis:    "Configure the Proxmox VE connection credentials and defaults.",
		HelpDescription: "POST: Set Proxmox address, admin token, TLS options, and default TTLs. Validates connectivity and privileges. Every POST must include all required fields including token_secret (write-only; not returned on GET) — full-resend semantics ensure each write is validated against the supplied credentials. GET: Read config (token_secret omitted). DELETE: Remove config (requires force=true).",
	}
}

// configWrite handles POST/PUT to <mount>/config.
//
// Steps:
//  1. Validate default_ttl <= default_max_ttl (when both set).
//  2. Build a PVE client with incoming credentials (b.newClient seam).
//  3. Call GetVersion (reachability + TLS).
//  4. Call GetPermissions, walk ancestor paths to assert User.Modify + Sys.Audit at /access/groups.
//  5. Overwrite warning if address/credentials changed.
//  6. Store config to key "config" (seal-wrapped by PathsSpecial).
//  7. Invalidate cached client so next use rebuilds.
func (b *backend) configWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	address := d.Get("address").(string)
	tokenID := d.Get("token_id").(string)
	tokenSecret := d.Get("token_secret").(string)
	tlsSkipVerify := d.Get("tls_skip_verify").(bool)
	caCert := d.Get("ca_cert").(string)
	defaultTTL := d.Get("default_ttl").(int)
	defaultMaxTTL := d.Get("default_max_ttl").(int)

	if address == "" {
		return logical.ErrorResponse("address is required"), nil
	}
	if tokenID == "" {
		return logical.ErrorResponse("token_id is required"), nil
	}
	if tokenSecret == "" {
		return logical.ErrorResponse("token_secret is required"), nil
	}

	// Validate TTL ordering (sanity guard; CalculateTTL would cap silently).
	if defaultTTL < 0 {
		return logical.ErrorResponse("default_ttl cannot be negative"), nil
	}
	if defaultMaxTTL < 0 {
		return logical.ErrorResponse("default_max_ttl cannot be negative"), nil
	}
	if defaultTTL > 0 && defaultMaxTTL > 0 && defaultTTL > defaultMaxTTL {
		return logical.ErrorResponse("default_ttl (%d) must not exceed default_max_ttl (%d)", defaultTTL, defaultMaxTTL), nil
	}

	cfg := &proxmoxConfig{
		Address:       address,
		TokenID:       tokenID,
		TokenSecret:   tokenSecret,
		TLSSkipVerify: tlsSkipVerify,
		CACert:        caCert,
		DefaultTTL:    defaultTTL,
		DefaultMaxTTL: defaultMaxTTL,
	}

	// Build a client from INCOMING credentials (not from cached client) so
	// we validate the new creds before storing them.
	client, err := b.newClient(cfg)
	if err != nil {
		return logical.ErrorResponse("failed to build PVE client: %s", err), nil
	}

	// Step 3: reachability + TLS check.
	var versionErr error
	if _, versionErr = client.GetVersion(ctx); versionErr != nil {
		if errors.Is(versionErr, pveapi.ErrUnauthenticated) {
			return logical.ErrorResponse("PVE /version returned 401 — admin token is unauthenticated; check config token_id/token_secret"), nil
		}
		if errors.Is(versionErr, pveapi.ErrForbidden) {
			return logical.ErrorResponse("PVE /version returned 403 — check address and token credentials"), nil
		}
		return logical.ErrorResponse("PVE connectivity check failed: %s", versionErr), nil
	}

	// Step 4: privilege check via permission tree with ancestor-walk.
	tree, err := client.GetPermissions(ctx)
	if err != nil {
		if errors.Is(err, pveapi.ErrUnauthenticated) {
			return logical.ErrorResponse("PVE returned 401 on GET /access/permissions — admin token is unauthenticated; check config token_id/token_secret"), nil
		}
		if errors.Is(err, pveapi.ErrForbidden) {
			return logical.ErrorResponse("PVE returned 403 on GET /access/permissions — token lacks required privileges"), nil
		}
		return logical.ErrorResponse("PVE GetPermissions failed: %s", err), nil
	}

	// Early-exit if the permission tree is empty.
	// An empty tree ({"data":{}}) means the admin token's effective ACL is
	// empty — most commonly because the token was created with privsep=1 (the
	// PVE default), which gives the token its own empty ACL and it inherits
	// nothing from its user account.  The fix is to recreate the token with
	// privsep=0, e.g.:
	//   pveum user token add <user> <tokenid> --privsep 0
	// (Confirmed PVE 9.2.10, PVE_PROBES.md Probe 6: a privsep=1 token returns
	// {"data":{}} from GET /access/permissions.)
	if len(tree) == 0 {
		return logical.ErrorResponse(
			"admin token has an empty permission tree — this almost always means the token was " +
				"created with privsep=1 (the PVE default), which gives the token its own empty ACL " +
				"and inherits nothing from its user account; " +
				"fix: recreate the token with --privsep 0, e.g. " +
				"\"pveum user token add <user> <tokenid> --privsep 0\"",
		), nil
	}

	if !tree.HasPrivilege("/access/groups", "User.Modify") {
		return logical.ErrorResponse(
			"admin token lacks User.Modify at /access/groups (or an ancestor with propagate=1); " +
				"grant: pveum acl modify /access/groups --user <admin> --role <role> --propagate 1",
		), nil
	}
	if !tree.HasPrivilege("/access/groups", "Sys.Audit") {
		return logical.ErrorResponse(
			"admin token lacks Sys.Audit at /access/groups (or an ancestor with propagate=1); " +
				"required for group-existence validation at role-write time",
		), nil
	}

	// Step 5: overwrite warning if connection credentials changed.
	var warnings []string
	existing, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("proxmox: read existing config: %w", err)
	}
	if existing != nil {
		if existing.Address != address || existing.TokenID != tokenID || existing.TokenSecret != tokenSecret {
			warnings = append(warnings, "config address/token changed; outstanding leases were issued against the previous admin token and may become non-revocable if the old token can no longer delete their users — revoke outstanding leases before changing connection credentials")
		}
	}

	// Step 6: store to "config" (seal-wrapped by PathsSpecial.SealWrapStorage).
	entry, err := logical.StorageEntryJSON("config", cfg)
	if err != nil {
		return nil, fmt.Errorf("proxmox: marshal config for storage: %w", err)
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, fmt.Errorf("proxmox: store config: %w", err)
	}

	// Step 7: invalidate cached client so getClient rebuilds from new config.
	b.invalidate(ctx, "config")

	resp := &logical.Response{}
	for _, w := range warnings {
		resp.AddWarning(w)
	}

	return resp, nil
}

// configRead handles GET to <mount>/config.
// Returns all fields EXCEPT token_secret (write-only credential).
func (b *backend) configRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"address":  cfg.Address,
			"token_id": cfg.TokenID,
			// token_secret is intentionally omitted — write-only.
			"tls_skip_verify": cfg.TLSSkipVerify,
			"ca_cert":         cfg.CACert,
			"default_ttl":     cfg.DefaultTTL,
			"default_max_ttl": cfg.DefaultMaxTTL,
		},
	}, nil
}

// configDelete handles DELETE to <mount>/config.
// Requires force=true to prevent accidental deletion while leases are active.
// Outstanding leases become non-revocable after config deletion (the engine
// cannot reach PVE to delete users without the admin token).
func (b *backend) configDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	force, ok := d.GetOk("force")
	if !ok || !force.(bool) {
		return logical.ErrorResponse("DELETE <mount>/config requires force=true; outstanding leases become non-revocable after config deletion — revoke all leases first, then re-run with force=true"), nil
	}

	if err := req.Storage.Delete(ctx, "config"); err != nil {
		return nil, fmt.Errorf("proxmox: delete config: %w", err)
	}

	// Clear cached client.
	b.invalidate(ctx, "config")

	return nil, nil
}
