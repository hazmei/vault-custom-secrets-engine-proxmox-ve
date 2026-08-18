// Package proxmox implements the Vault secrets engine for Proxmox VE.
//
// SCAFFOLD STUB — this file contains only the minimum needed to satisfy
// cmd/vault-plugin-secrets-proxmox/main.go so that `go build ./...` passes.
//
// The real backend (path registrations, Secret types, WAL, client cache,
// InvalidateFunc, etc.) is implemented in the next phase. Nothing below
// should be read as final design — it exists solely to anchor the Factory
// symbol that main.go imports.
//
// See docs/IMPLEMENTATION_PLAN.md §backend.go for the full specification.
package proxmox

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// Factory is the public entry point called by plugin.ServeMultiplex.
// It satisfies the logical.Factory signature:
//
//	type Factory func(context.Context, *logical.BackendConfig) (logical.Backend, error)
//
// STUB: returns a minimal framework.Backend with BackendType set to TypeLogical.
// Replace with the real newBackend() implementation in the next phase.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := &framework.Backend{
		BackendType: logical.TypeLogical,
		Help:        "Proxmox VE dynamic secrets engine (scaffold stub — not yet implemented).",
	}

	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}

	return b, nil
}
