// Package proxmox — unit tests for path_config.go.
//
// Uses the mock PVE client injected via b.newClient to test:
//   - Config write: validation, connectivity check, permission ancestor-walk
//   - Config read: excludes token_secret
//   - Config delete: requires force=true
//   - TTL ordering validation: default_ttl > default_max_ttl rejected
//   - Overwrite warning when credentials change
package proxmox

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	pveapi "github.com/hazmei/vault-plugin-secrets-proxmox/internal/pveapi"
)

// newTestBackend builds a backend with an in-memory storage and a mock PVE
// client factory. The mock's behavior is configured via the mockSetup func.
func newTestBackend(t *testing.T, mockSetup func(*pveapi.MockClient)) (*backend, logical.Storage) {
	t.Helper()

	ctx := context.Background()
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}

	b, err := newBackend(ctx, config)
	if err != nil {
		t.Fatalf("newBackend: %v", err)
	}

	mc := &pveapi.MockClient{}
	if mockSetup != nil {
		mockSetup(mc)
	}

	// Inject mock factory: ignore the incoming config and always return mc.
	b.newClient = func(_ *proxmoxConfig) (pveapi.Client, error) {
		return mc, nil
	}

	return b, config.StorageView
}

// writeConfig is a helper that sends a POST to <mount>/config with the given
// field values. Returns the response and any framework-level error.
func writeConfig(ctx context.Context, b *backend, storage logical.Storage, data map[string]interface{}) (*logical.Response, error) {
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data:      data,
	}
	return b.HandleRequest(ctx, req)
}

func readConfig(ctx context.Context, b *backend, storage logical.Storage) (*logical.Response, error) {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   storage,
	}
	return b.HandleRequest(ctx, req)
}

func deleteConfig(ctx context.Context, b *backend, storage logical.Storage, force bool) (*logical.Response, error) {
	req := &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "config",
		Storage:   storage,
		Data:      map[string]interface{}{"force": force},
	}
	return b.HandleRequest(ctx, req)
}

// defaultMock returns a mock client with default happy-path behaviour:
// GetVersion returns "9.2.10" and GetPermissions returns a tree with
// User.Modify + Sys.Audit at /access/groups (propagate=1).
func defaultMock() func(*pveapi.MockClient) {
	return func(mc *pveapi.MockClient) {
		mc.GetPermissionsResult = pveapi.PermissionTree{
			"/access/groups": {
				"User.Modify": 1,
				"Sys.Audit":   1,
			},
		}
	}
}

// validConfigData returns the minimum valid config POST data.
func validConfigData() map[string]interface{} {
	return map[string]interface{}{
		"address":      "https://pve.example.com:8006",
		"token_id":     "vault-admin@pve!mytoken",
		"token_secret": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
	}
}

// ── Write tests ──────────────────────────────────────────────────────────────

func TestConfigWrite_HappyPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	b, storage := newTestBackend(t, defaultMock())

	resp, err := writeConfig(ctx, b, storage, validConfigData())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %s", resp.Error())
	}
}

func TestConfigWrite_DefaultTTLExceedsMaxTTL_Rejected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	b, storage := newTestBackend(t, defaultMock())

	data := validConfigData()
	data["default_ttl"] = 7200
	data["default_max_ttl"] = 3600

	resp, err := writeConfig(ctx, b, storage, data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.IsError() {
		t.Fatal("expected error response for default_ttl > default_max_ttl")
	}
}

func TestConfigWrite_NegativeDefaultTTL_Rejected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	b, storage := newTestBackend(t, defaultMock())

	data := validConfigData()
	data["default_ttl"] = -3600

	resp, err := writeConfig(ctx, b, storage, data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.IsError() {
		t.Fatal("expected error response for negative default_ttl")
	}
	// The SDK rejects TypeDurationSecond negative values at the framework layer
	// before our handler runs. Either the framework message ("cannot provide
	// negative value") or our explicit guard ("default_ttl cannot be negative")
	// is acceptable — what matters is that the request is rejected.
	if !strings.Contains(resp.Error().Error(), "negative") {
		t.Errorf("error should mention 'negative'; got: %q", resp.Error())
	}
}

func TestConfigWrite_NegativeDefaultMaxTTL_Rejected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	b, storage := newTestBackend(t, defaultMock())

	data := validConfigData()
	data["default_max_ttl"] = -86400

	resp, err := writeConfig(ctx, b, storage, data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.IsError() {
		t.Fatal("expected error response for negative default_max_ttl")
	}
	// The SDK rejects TypeDurationSecond negative values at the framework layer
	// before our handler runs. Either the framework message ("cannot provide
	// negative value") or our explicit guard ("default_max_ttl cannot be negative")
	// is acceptable — what matters is that the request is rejected.
	if !strings.Contains(resp.Error().Error(), "negative") {
		t.Errorf("error should mention 'negative'; got: %q", resp.Error())
	}
}

func TestConfigWrite_MissingAddress_Rejected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	b, storage := newTestBackend(t, defaultMock())

	data := validConfigData()
	delete(data, "address")

	resp, err := writeConfig(ctx, b, storage, data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.IsError() {
		t.Fatal("expected error response for missing address")
	}
}

func TestConfigWrite_GetVersionFails_Rejected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		mc.GetVersionFn = func(_ context.Context) (string, error) {
			return "", errors.New("connection refused")
		}
	})

	resp, err := writeConfig(ctx, b, storage, validConfigData())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.IsError() {
		t.Fatal("expected error response when GetVersion fails")
	}
}

func TestConfigWrite_GetVersion401_RejectedWithAuthDiagnostic(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		mc.GetVersionFn = func(_ context.Context) (string, error) {
			return "", fmt.Errorf("wrapped: %w", pveapi.ErrUnauthenticated)
		}
	})

	resp, err := writeConfig(ctx, b, storage, validConfigData())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.IsError() {
		t.Fatal("expected error response when GetVersion returns 401")
	}
	errMsg := strings.ToLower(resp.Error().Error())
	if !strings.Contains(errMsg, "401") || !strings.Contains(errMsg, "unauthenticated") {
		t.Errorf("error should clearly mention 401 unauthenticated; got: %q", resp.Error())
	}
}

func TestConfigWrite_GetPermissions403_Rejected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		mc.GetPermissionsFn = func(_ context.Context) (pveapi.PermissionTree, error) {
			return nil, pveapi.ErrForbidden
		}
	})

	resp, err := writeConfig(ctx, b, storage, validConfigData())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.IsError() {
		t.Fatal("expected error response when GetPermissions returns 403")
	}
}

func TestConfigWrite_GetPermissions401_RejectedWithAuthDiagnostic(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		mc.GetPermissionsFn = func(_ context.Context) (pveapi.PermissionTree, error) {
			return nil, fmt.Errorf("wrapped: %w", pveapi.ErrUnauthenticated)
		}
	})

	resp, err := writeConfig(ctx, b, storage, validConfigData())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.IsError() {
		t.Fatal("expected error response when GetPermissions returns 401")
	}
	errMsg := strings.ToLower(resp.Error().Error())
	if !strings.Contains(errMsg, "401") || !strings.Contains(errMsg, "unauthenticated") {
		t.Errorf("error should clearly mention 401 unauthenticated; got: %q", resp.Error())
	}
}

func TestConfigWrite_MissingUserModify_Rejected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		// Return a tree without User.Modify.
		mc.GetPermissionsResult = pveapi.PermissionTree{
			"/access/groups": {"Sys.Audit": 1},
		}
	})

	resp, err := writeConfig(ctx, b, storage, validConfigData())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.IsError() {
		t.Fatal("expected error response for missing User.Modify")
	}
}

func TestConfigWrite_MissingSysAudit_Rejected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		// Return a tree without Sys.Audit.
		mc.GetPermissionsResult = pveapi.PermissionTree{
			"/access/groups": {"User.Modify": 1},
		}
	})

	resp, err := writeConfig(ctx, b, storage, validConfigData())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.IsError() {
		t.Fatal("expected error response for missing Sys.Audit")
	}
}

func TestConfigWrite_UserModifyWithPropagate0AtParent_Rejected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		// /access has User.Modify with propagate=0 — does NOT satisfy /access/groups.
		mc.GetPermissionsResult = pveapi.PermissionTree{
			"/access": {"User.Modify": 0, "Sys.Audit": 0},
		}
	})

	resp, err := writeConfig(ctx, b, storage, validConfigData())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.IsError() {
		t.Fatal("expected error: propagate=0 at parent should not satisfy /access/groups")
	}
}

func TestConfigWrite_UserModifyExactPathWithPropagate0_Accepted(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		// Exact path /access/groups with propagate=0 is still an exact match → ok.
		mc.GetPermissionsResult = pveapi.PermissionTree{
			"/access/groups": {"User.Modify": 0, "Sys.Audit": 0},
		}
	})

	resp, err := writeConfig(ctx, b, storage, validConfigData())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %s", resp.Error())
	}
}

func TestConfigWrite_OverwriteWarning(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	b, storage := newTestBackend(t, defaultMock())

	// Write initial config.
	if _, err := writeConfig(ctx, b, storage, validConfigData()); err != nil {
		t.Fatalf("first write: %v", err)
	}

	// Overwrite with different credentials.
	data := validConfigData()
	data["token_secret"] = "ffffffff-0000-1111-2222-333333333333"
	resp, err := writeConfig(ctx, b, storage, data)
	if err != nil {
		t.Fatalf("second write: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error: %s", resp.Error())
	}
	if len(resp.Warnings) == 0 {
		t.Error("expected overwrite warning when credentials change")
	}
}

// ── Read tests ───────────────────────────────────────────────────────────────

func TestConfigRead_ExcludesTokenSecret(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	b, storage := newTestBackend(t, defaultMock())

	if _, err := writeConfig(ctx, b, storage, validConfigData()); err != nil {
		t.Fatalf("write: %v", err)
	}

	resp, err := readConfig(ctx, b, storage)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
		return
	}

	if _, present := resp.Data["token_secret"]; present {
		t.Error("token_secret must NOT be present in GET /config response")
	}
}

func TestConfigRead_ReturnsExpectedFields(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	b, storage := newTestBackend(t, defaultMock())

	data := validConfigData()
	data["default_ttl"] = 3600
	data["default_max_ttl"] = 86400
	data["tls_skip_verify"] = true

	if _, err := writeConfig(ctx, b, storage, data); err != nil {
		t.Fatalf("write: %v", err)
	}

	resp, err := readConfig(ctx, b, storage)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	for _, field := range []string{"address", "token_id", "tls_skip_verify", "default_ttl", "default_max_ttl"} {
		if _, ok := resp.Data[field]; !ok {
			t.Errorf("expected field %q in GET response", field)
		}
	}

	if resp.Data["address"] != data["address"] {
		t.Errorf("address = %v; want %v", resp.Data["address"], data["address"])
	}
	if resp.Data["token_id"] != data["token_id"] {
		t.Errorf("token_id = %v; want %v", resp.Data["token_id"], data["token_id"])
	}
}

func TestConfigRead_NilWhenNotSet(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	b, storage := newTestBackend(t, nil)

	resp, err := readConfig(ctx, b, storage)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil {
		t.Errorf("expected nil response when config not set, got %v", resp)
	}
}

// ── Delete tests ─────────────────────────────────────────────────────────────

func TestConfigDelete_WithoutForce_Rejected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	b, storage := newTestBackend(t, defaultMock())

	if _, err := writeConfig(ctx, b, storage, validConfigData()); err != nil {
		t.Fatalf("write: %v", err)
	}

	resp, err := deleteConfig(ctx, b, storage, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.IsError() {
		t.Fatal("expected error response for DELETE without force=true")
	}
}

// TestConfigDelete_WithoutForce_ExplainsCLIFlagCollision covers DR-5: an
// operator who runs `vault delete -force <mount>/config` passes a CLI
// skip-confirmation FLAG that transmits no `force` data value, so they land on
// this rejection with no other clue why the flag they typed was ignored. The
// message must name the collision and both correct invocations.
func TestConfigDelete_WithoutForce_ExplainsCLIFlagCollision(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	b, storage := newTestBackend(t, defaultMock())

	if _, err := writeConfig(ctx, b, storage, validConfigData()); err != nil {
		t.Fatalf("write: %v", err)
	}

	resp, err := deleteConfig(ctx, b, storage, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.IsError() {
		t.Fatal("expected error response for DELETE without force=true")
	}

	msg := resp.Error().Error()
	for _, want := range []string{
		"force=true",          // the required data parameter
		"vault delete -force", // the colliding CLI flag, named explicitly
		"?force=true",         // the curl / query-parameter fallback
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("delete guard message missing %q; got: %s", want, msg)
		}
	}
}

// TestConfigForceFieldDocumentsCLIFlagCollision covers the DR-5 acceptance
// criterion that the `force` field Description itself (what `vault path-help`
// renders) states the flag does not satisfy the parameter.
func TestConfigForceFieldDocumentsCLIFlagCollision(t *testing.T) {
	t.Parallel()
	b, _ := newTestBackend(t, nil)

	// Pin to the config path explicitly. Taking the first path that happens to
	// declare a `force` field would let this assertion silently relocate to a
	// different path if one ever adds its own `force`, and then pass (or fail)
	// for the wrong reason.
	var forceField *framework.FieldSchema
	for _, p := range b.Paths {
		if p.Pattern != "config" {
			continue
		}
		forceField = p.Fields["force"]
		break
	}
	if forceField == nil {
		t.Fatal("the `config` path does not declare a `force` field")
		return
	}

	for _, want := range []string{
		"vault delete -force",
		"force=true",
		"?force=true",
	} {
		if !strings.Contains(forceField.Description, want) {
			t.Errorf("force field Description missing %q; got: %s", want, forceField.Description)
		}
	}
}

func TestConfigDelete_WithForce_Succeeds(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	b, storage := newTestBackend(t, defaultMock())

	if _, err := writeConfig(ctx, b, storage, validConfigData()); err != nil {
		t.Fatalf("write: %v", err)
	}

	resp, err := deleteConfig(ctx, b, storage, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %s", resp.Error())
	}

	// Config should now be gone.
	readResp, err := readConfig(ctx, b, storage)
	if err != nil {
		t.Fatalf("read after delete: %v", err)
	}
	if readResp != nil {
		t.Error("expected nil read response after config deletion")
	}
}

func TestConfigDelete_ClearsClientCache(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	b, storage := newTestBackend(t, defaultMock())

	if _, err := writeConfig(ctx, b, storage, validConfigData()); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Warm the cache.
	if _, err := b.getClient(ctx, storage); err != nil {
		t.Fatalf("getClient before delete: %v", err)
	}

	if _, err := deleteConfig(ctx, b, storage, true); err != nil {
		t.Fatalf("delete: %v", err)
	}

	b.clientMu.RLock()
	cachedClient := b.client
	b.clientMu.RUnlock()

	if cachedClient != nil {
		t.Error("expected cached client to be nil after config deletion")
	}
}

// ── Round-trip test ──────────────────────────────────────────────────────────

func TestConfigWriteReadDeleteRoundTrip(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	b, storage := newTestBackend(t, defaultMock())

	data := validConfigData()
	data["default_ttl"] = 1800
	data["default_max_ttl"] = 7200
	data["ca_cert"] = "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----"

	// Write.
	if _, err := writeConfig(ctx, b, storage, data); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Read back — token_secret must be absent.
	resp, err := readConfig(ctx, b, storage)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if resp == nil {
		t.Fatal("nil read response after write")
		return
	}
	if _, present := resp.Data["token_secret"]; present {
		t.Error("token_secret must not be in read response")
	}
	if resp.Data["default_ttl"] != 1800 {
		t.Errorf("default_ttl = %v; want 1800", resp.Data["default_ttl"])
	}

	// Delete without force — should fail.
	resp, err = deleteConfig(ctx, b, storage, false)
	if err != nil {
		t.Fatalf("delete without force: %v", err)
	}
	if !resp.IsError() {
		t.Fatal("expected error from delete without force")
	}

	// Delete with force — should succeed.
	if _, err = deleteConfig(ctx, b, storage, true); err != nil {
		t.Fatalf("delete with force: %v", err)
	}

	// Read after delete — should be nil.
	resp, err = readConfig(ctx, b, storage)
	if err != nil {
		t.Fatalf("read after delete: %v", err)
	}
	if resp != nil {
		t.Error("expected nil response after delete")
	}
}

// TestConfigWrite_EmptyPermissionTree_Privsep1Diagnostic asserts that when
// GetPermissions returns an empty PermissionTree ({"data":{}}), configWrite
// returns a clear error explaining the privsep=1 root cause.
//
// This is grounded in PVE_PROBES.md Probe 6: a token created with privsep=1
// (the PVE default) returns an empty permissions tree because it has its own
// empty ACL and inherits nothing from its user account.  The fix is to
// recreate the token with --privsep 0.
func TestConfigWrite_EmptyPermissionTree_Privsep1Diagnostic(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		// Simulate a token created with privsep=1: GET /access/permissions
		// returns {"data":{}} — an empty permission tree.
		mc.GetPermissionsResult = pveapi.PermissionTree{}
	})

	resp, err := writeConfig(ctx, b, storage, validConfigData())
	if err != nil {
		t.Fatalf("unexpected framework error: %v", err)
	}
	if !resp.IsError() {
		t.Fatal("expected error response when permission tree is empty (privsep=1 scenario)")
	}

	errMsg := resp.Error().Error()
	// The error must mention privsep=0 so the operator knows the fix.
	if !strings.Contains(strings.ToLower(errMsg), "privsep") {
		t.Errorf("error should mention privsep; got: %q", errMsg)
	}
	if !strings.Contains(errMsg, "0") {
		t.Errorf("error should mention privsep 0 (the fix); got: %q", errMsg)
	}
}
