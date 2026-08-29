// Package proxmox implements the Vault secrets engine for Proxmox VE.
//
// This engine issues dynamic Proxmox VE API tokens by creating throwaway
// per-lease PVE users, adding them to operator-pre-created PVE groups (which
// cluster admins have bound to desired ACL roles), and minting API tokens on
// those users. Revocation deletes the user, cascading to remove tokens,
// group memberships, and ACL entries in one call.
//
// Target: Proxmox VE 9.2.10. Built on hashicorp/vault/sdk.
// See docs/ARCHITECTURE.md and docs/IMPLEMENTATION_PLAN.md for the full spec.
package proxmox

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hazmei/vault-plugin-secrets-proxmox/internal/pveapi"
)

// backend is the root struct for the Proxmox VE secrets engine.
type backend struct {
	*framework.Backend

	// clientMu guards the cached PVE API client.
	clientMu sync.RWMutex
	// client is the cached PVE API client. Nil until first use or after
	// config invalidation. Built lazily by getClient.
	client pveapi.Client

	// roleLock serializes roleWrite's read-modify-write (load existing role →
	// merge fields → store). Without this, concurrent updates to the same role
	// can interleave and the last writer silently drops fields from earlier
	// concurrent writers. sync.Mutex zero value is ready to use.
	roleLock sync.Mutex

	// newClient is the factory used by the config-write handler to build a
	// PVE client from incoming credentials BEFORE storing config.
	// Defaults to the real constructor; overridden in unit tests to inject
	// a mock. This seam is required because the config-write validation
	// builds a client from incoming creds (not from the stored config cache).
	newClient func(cfg *proxmoxConfig) (pveapi.Client, error)
}

// Factory is the public entry point called by plugin.ServeMultiplex.
// It satisfies the logical.Factory signature.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	return newBackend(ctx, conf)
}

// newBackend constructs and initialises the backend.
func newBackend(ctx context.Context, conf *logical.BackendConfig) (*backend, error) {
	b := &backend{}

	// Default newClient factory: build a real httpClient from config.
	b.newClient = func(cfg *proxmoxConfig) (pveapi.Client, error) {
		return pveapi.NewClient(pveapi.ClientConfig{
			Address:       cfg.Address,
			TokenID:       cfg.TokenID,
			TokenSecret:   cfg.TokenSecret,
			TLSSkipVerify: cfg.TLSSkipVerify,
			CACert:        cfg.CACert,
		})
	}

	b.Backend = &framework.Backend{
		Help:        "Vault secrets engine for Proxmox VE dynamic API tokens.",
		BackendType: logical.TypeLogical,

		PathsSpecial: &logical.Paths{
			// Seal-wrap the config entry so token_secret is protected by the
			// active seal (Transit auto-unseal, PKCS11, etc.).
			SealWrapStorage: []string{"config"},
		},

		Paths: framework.PathAppend(
			[]*framework.Path{pathConfig(b)},
			pathRoles(b),
			[]*framework.Path{pathCreds(b)},
		),

		Secrets:           []*framework.Secret{secretToken(b), secretPassword(b)},
		WALRollback:       b.walRollback,
		WALRollbackMinAge: 5 * time.Minute,

		Invalidate: b.invalidate,
	}

	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}

	return b, nil
}

// getClient returns the cached PVE API client, building it from stored config
// if necessary. Returns an error if no config has been written yet.
func (b *backend) getClient(ctx context.Context, storage logical.Storage) (pveapi.Client, error) {
	b.clientMu.RLock()
	client := b.client
	b.clientMu.RUnlock()
	if client != nil {
		return client, nil
	}

	// Not cached — build from stored config.
	b.clientMu.Lock()
	defer b.clientMu.Unlock()

	// Double-check after acquiring write lock.
	if b.client != nil {
		return b.client, nil
	}

	cfg, err := getConfig(ctx, storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, fmt.Errorf("proxmox: no configuration found; write config to <mount>/config first")
	}

	client, err = b.newClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("proxmox: build PVE client: %w", err)
	}

	b.client = client
	return client, nil
}

// invalidate clears the cached client when the config key changes.
// Called by the Vault framework when another node writes to storage.
func (b *backend) invalidate(_ context.Context, key string) {
	if key == "config" {
		b.clientMu.Lock()
		b.client = nil
		b.clientMu.Unlock()
	}
}

// proxmoxConfig is the config stored at storage key "config".
// The literal key "config" is used everywhere — it must match
// PathsSpecial.SealWrapStorage and the invalidate comparison.
type proxmoxConfig struct {
	Address       string `json:"address"`
	TokenID       string `json:"token_id"`     // returned on GET (identity only)
	TokenSecret   string `json:"token_secret"` // NEVER returned on GET
	TLSSkipVerify bool   `json:"tls_skip_verify"`
	CACert        string `json:"ca_cert"`
	DefaultTTL    int    `json:"default_ttl"`     // seconds; 0 = unset (fallback to Vault system default)
	DefaultMaxTTL int    `json:"default_max_ttl"` // seconds; 0 = unset
}

// getConfig loads and decodes the config entry from storage.
// Returns (nil, nil) when no config has been written.
func getConfig(ctx context.Context, storage logical.Storage) (*proxmoxConfig, error) {
	entry, err := storage.Get(ctx, "config")
	if err != nil {
		return nil, fmt.Errorf("proxmox: read config from storage: %w", err)
	}
	if entry == nil {
		return nil, nil
	}

	var cfg proxmoxConfig
	if err := json.Unmarshal(entry.Value, &cfg); err != nil {
		return nil, fmt.Errorf("proxmox: decode config: %w", err)
	}

	return &cfg, nil
}
