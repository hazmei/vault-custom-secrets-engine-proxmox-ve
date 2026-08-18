// Package main is the entry point for the vault-plugin-secrets-proxmox plugin binary.
// It calls plugin.ServeMultiplex with BackendFactoryFunc pointing at the root package
// Factory. TLSProviderFunc is intentionally omitted — Vault v5+ AutoMTLS handles TLS
// negotiation without it.
package main

import (
	"os"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/plugin"
	proxmox "github.com/hazmei/vault-plugin-secrets-proxmox"
)

func main() {
	logger := hclog.New(&hclog.LoggerOptions{})

	err := plugin.ServeMultiplex(&plugin.ServeOpts{
		BackendFactoryFunc: proxmox.Factory,
	})
	if err != nil {
		logger.Error("plugin shutting down", "error", err)
		os.Exit(1)
	}
}
