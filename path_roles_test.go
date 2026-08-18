// Package proxmox — unit tests for path_roles.go.
//
// Covers:
//   - Role CRUD (write, read, list, delete)
//   - TTL validation (ttl > max_ttl rejected)
//   - Userid length budget rejection at write time
//   - Realm validation (invalid charset, missing)
//   - Group existence check: ErrGroupNotFound → clear error message (DR-2)
//   - Realm.AllocateUser missing → rejected
//   - Per-group-path User.Modify check: propagate=0 at /access/groups → rejected
//   - ttls() fallback chain (both-unset, role-set, config-default, mixed)
//   - cappedMaxTTL 4-case: (0,X)→X, (X,0)→X, (0,0)→0, (A,B)→min(A,B)
package proxmox

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	pveapi "github.com/hazmei/vault-plugin-secrets-proxmox/internal/pveapi"
)

// ── Helpers ──────────────────────────────────────────────────────────────────

// writeRole is a helper that sends a POST to <mount>/roles/:name.
func writeRole(ctx context.Context, b *backend, storage logical.Storage, name string, data map[string]interface{}) (*logical.Response, error) {
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/" + name,
		Storage:   storage,
		Data:      data,
	}
	return b.HandleRequest(ctx, req)
}

// readRole is a helper that sends a GET to <mount>/roles/:name.
func readRole(ctx context.Context, b *backend, storage logical.Storage, name string) (*logical.Response, error) {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "roles/" + name,
		Storage:   storage,
	}
	return b.HandleRequest(ctx, req)
}

// listRoles is a helper that sends a LIST to <mount>/roles.
func listRoles(ctx context.Context, b *backend, storage logical.Storage) (*logical.Response, error) {
	req := &logical.Request{
		Operation: logical.ListOperation,
		Path:      "roles/",
		Storage:   storage,
	}
	return b.HandleRequest(ctx, req)
}

// updateRole is a helper that sends a PUT (UpdateOperation) to <mount>/roles/:name.
// Only the fields present in data are sent — simulating a partial-update request.
func updateRole(ctx context.Context, b *backend, storage logical.Storage, name string, data map[string]interface{}) (*logical.Response, error) {
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/" + name,
		Storage:   storage,
		Data:      data,
	}
	return b.HandleRequest(ctx, req)
}

// deleteRole is a helper that sends a DELETE to <mount>/roles/:name.
func deleteRole(ctx context.Context, b *backend, storage logical.Storage, name string) (*logical.Response, error) {
	req := &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "roles/" + name,
		Storage:   storage,
	}
	return b.HandleRequest(ctx, req)
}

// validRoleData returns a minimal valid role POST data map.
func validRoleData() map[string]interface{} {
	return map[string]interface{}{
		"group":       "vault-vm-admins",
		"user_prefix": "vault",
		"realm":       "pve",
		"ttl":         3600,
		"max_ttl":     86400,
	}
}

// setupBackendWithConfig writes a valid config and returns the backend and storage.
// The mock client is configured with full privileges by default.
func setupBackendWithConfig(t *testing.T, mockSetup func(*pveapi.MockClient)) (*backend, logical.Storage) {
	t.Helper()
	ctx := context.Background()

	// Use defaultMock to provide config-write permissions, then layer on
	// the caller's mockSetup for role-write-specific permissions.
	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		// Start with config-write-compatible permissions.
		mc.GetPermissionsResult = pveapi.PermissionTree{
			"/access/groups": {
				"User.Modify": 1,
				"Sys.Audit":   1,
			},
			"/access/realm/pve": {
				"Realm.AllocateUser": 1,
			},
		}
		// Pre-seed the "vault-vm-admins" group so GetGroup succeeds.
		mc.Groups = map[string]bool{
			"vault-vm-admins": true,
		}
		if mockSetup != nil {
			mockSetup(mc)
		}
	})

	// Write a valid config so role-write can getConfig successfully.
	if _, err := writeConfig(ctx, b, storage, validConfigData()); err != nil {
		t.Fatalf("setupBackendWithConfig: write config: %v", err)
	}

	return b, storage
}

// fullPermTree returns a PermissionTree with all required privileges for role write.
// The per-group path /access/groups/vault-vm-admins is included with propagate=1.
func fullPermTree(group string) pveapi.PermissionTree {
	return pveapi.PermissionTree{
		"/access/groups": {
			"User.Modify": 1,
			"Sys.Audit":   1,
		},
		"/access/groups/" + group: {
			"User.Modify": 1,
		},
		"/access/realm/pve": {
			"Realm.AllocateUser": 1,
		},
	}
}

// ── CRUD tests ────────────────────────────────────────────────────────────────

func TestRoleWrite_HappyPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	b, storage := setupBackendWithConfig(t, func(mc *pveapi.MockClient) {
		mc.GetPermissionsResult = fullPermTree("vault-vm-admins")
	})

	resp, err := writeRole(ctx, b, storage, "myrole", validRoleData())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %s", resp.Error())
	}
}

func TestRoleRead_AfterWrite(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	b, storage := setupBackendWithConfig(t, func(mc *pveapi.MockClient) {
		mc.GetPermissionsResult = fullPermTree("vault-vm-admins")
	})

	data := validRoleData()
	if _, err := writeRole(ctx, b, storage, "myrole", data); err != nil {
		t.Fatalf("write: %v", err)
	}

	resp, err := readRole(ctx, b, storage, "myrole")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response on read")
	}

	for _, field := range []string{"group", "user_prefix", "realm", "ttl", "max_ttl"} {
		if _, ok := resp.Data[field]; !ok {
			t.Errorf("expected field %q in GET response", field)
		}
	}
	if resp.Data["group"] != "vault-vm-admins" {
		t.Errorf("group = %v; want vault-vm-admins", resp.Data["group"])
	}
	if resp.Data["realm"] != "pve" {
		t.Errorf("realm = %v; want pve", resp.Data["realm"])
	}
}

func TestRoleRead_NilWhenNotSet(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	b, storage := setupBackendWithConfig(t, nil)

	resp, err := readRole(ctx, b, storage, "nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil {
		t.Errorf("expected nil response for nonexistent role; got %v", resp)
	}
}

func TestRoleList_AfterMultipleWrites(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	b, storage := setupBackendWithConfig(t, func(mc *pveapi.MockClient) {
		mc.GetPermissionsResult = fullPermTree("vault-vm-admins")
	})

	for _, name := range []string{"role-a", "role-b", "role-c"} {
		if _, err := writeRole(ctx, b, storage, name, validRoleData()); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	resp, err := listRoles(ctx, b, storage)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil list response")
	}

	keys, ok := resp.Data["keys"].([]string)
	if !ok {
		t.Fatalf("expected keys []string; got %T", resp.Data["keys"])
	}

	nameSet := make(map[string]bool)
	for _, k := range keys {
		nameSet[k] = true
	}
	for _, want := range []string{"role-a", "role-b", "role-c"} {
		if !nameSet[want] {
			t.Errorf("expected role %q in list; got %v", want, keys)
		}
	}
}

func TestRoleDelete_RemovesRole(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	b, storage := setupBackendWithConfig(t, func(mc *pveapi.MockClient) {
		mc.GetPermissionsResult = fullPermTree("vault-vm-admins")
	})

	if _, err := writeRole(ctx, b, storage, "myrole", validRoleData()); err != nil {
		t.Fatalf("write: %v", err)
	}

	resp, err := deleteRole(ctx, b, storage, "myrole")
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error response: %s", resp.Error())
	}

	// Role should now be gone.
	readResp, err := readRole(ctx, b, storage, "myrole")
	if err != nil {
		t.Fatalf("read after delete: %v", err)
	}
	if readResp != nil {
		t.Error("expected nil read response after role deletion")
	}
}

// ── TTL validation ────────────────────────────────────────────────────────────

func TestRoleWrite_TTLExceedsMaxTTL_Rejected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	b, storage := setupBackendWithConfig(t, nil)

	data := validRoleData()
	data["ttl"] = 86400
	data["max_ttl"] = 3600

	resp, err := writeRole(ctx, b, storage, "myrole", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.IsError() {
		t.Error("expected error response for ttl > max_ttl")
	}
}

func TestRoleWrite_NegativeTTL_Rejected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	b, storage := setupBackendWithConfig(t, nil)

	data := validRoleData()
	data["ttl"] = -3600

	resp, err := writeRole(ctx, b, storage, "myrole", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.IsError() {
		t.Error("expected error response for negative ttl")
	}
	// The SDK rejects TypeDurationSecond negative values at the framework layer
	// before our handler runs. Either the framework message ("cannot provide
	// negative value") or our explicit guard ("ttl cannot be negative") is
	// acceptable — what matters is that the request is rejected.
	errMsg := resp.Error().Error()
	if !strings.Contains(errMsg, "negative") {
		t.Errorf("error should mention 'negative'; got: %q", errMsg)
	}
}

func TestRoleWrite_NegativeMaxTTL_Rejected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	b, storage := setupBackendWithConfig(t, nil)

	data := validRoleData()
	data["max_ttl"] = -7200

	resp, err := writeRole(ctx, b, storage, "myrole", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.IsError() {
		t.Error("expected error response for negative max_ttl")
	}
	// The SDK rejects TypeDurationSecond negative values at the framework layer
	// before our handler runs. Either the framework message ("cannot provide
	// negative value") or our explicit guard ("max_ttl cannot be negative") is
	// acceptable — what matters is that the request is rejected.
	errMsg := resp.Error().Error()
	if !strings.Contains(errMsg, "negative") {
		t.Errorf("error should mention 'negative'; got: %q", errMsg)
	}
}

func TestRoleWrite_TTLEqualsMaxTTL_Accepted(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	b, storage := setupBackendWithConfig(t, func(mc *pveapi.MockClient) {
		mc.GetPermissionsResult = fullPermTree("vault-vm-admins")
	})

	data := validRoleData()
	data["ttl"] = 3600
	data["max_ttl"] = 3600

	resp, err := writeRole(ctx, b, storage, "myrole", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error: %s", resp.Error())
	}
}

func TestRoleWrite_TTLUnset_Accepted(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	b, storage := setupBackendWithConfig(t, func(mc *pveapi.MockClient) {
		mc.GetPermissionsResult = fullPermTree("vault-vm-admins")
	})

	data := validRoleData()
	delete(data, "ttl")
	delete(data, "max_ttl")

	resp, err := writeRole(ctx, b, storage, "myrole", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error: %s", resp.Error())
	}
}

// ── Realm validation ──────────────────────────────────────────────────────────

func TestRoleWrite_RealmDefaultsToPVE(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	b, storage := setupBackendWithConfig(t, func(mc *pveapi.MockClient) {
		mc.GetPermissionsResult = fullPermTree("vault-vm-admins")
	})

	data := validRoleData()
	delete(data, "realm") // let it default

	resp, err := writeRole(ctx, b, storage, "myrole", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error: %s", resp.Error())
	}

	// Read back and verify realm defaulted to "pve".
	readResp, err := readRole(ctx, b, storage, "myrole")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if readResp.Data["realm"] != "pve" {
		t.Errorf("realm = %v; want pve", readResp.Data["realm"])
	}
}

func TestRoleWrite_InvalidRealm_Rejected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	b, storage := setupBackendWithConfig(t, nil)

	data := validRoleData()
	data["realm"] = "1invalid" // must start with letter

	resp, err := writeRole(ctx, b, storage, "myrole", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.IsError() {
		t.Error("expected error response for invalid realm starting with digit")
	}
}

func TestRoleWrite_InvalidRealm_AtSign_Rejected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	b, storage := setupBackendWithConfig(t, nil)

	data := validRoleData()
	data["realm"] = "pve@bad"

	resp, err := writeRole(ctx, b, storage, "myrole", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.IsError() {
		t.Error("expected error response for realm with '@'")
	}
}

// ── Userid component validation ───────────────────────────────────────────────

func TestRoleWrite_InvalidUserPrefix_Rejected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	b, storage := setupBackendWithConfig(t, nil)

	data := validRoleData()
	data["user_prefix"] = "vault:admin" // colon forbidden

	resp, err := writeRole(ctx, b, storage, "myrole", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.IsError() {
		t.Error("expected error response for user_prefix with ':'")
	}
}

func TestRoleWrite_InvalidRoleName_AtSign_Rejected(t *testing.T) {
	t.Parallel()
	// The path framework normalizes role names from URLs; test validateUserComponent
	// directly since role names with '@' must be rejected.
	if err := validateUserComponent("vault@bad"); err == nil {
		t.Error("validateUserComponent(\"vault@bad\") should return an error")
	}
	if err := validateUserComponent("role!name"); err == nil {
		t.Error("validateUserComponent(\"role!name\") should return an error")
	}
}

// ── Length budget validation ──────────────────────────────────────────────────

func TestRoleWrite_LengthBudgetExceeded_Rejected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	b, storage := setupBackendWithConfig(t, nil)

	// prefix=26 + role=25 + realm=pve(3) → 26+1+25+1+8+1+3 = 65 > 64
	data := validRoleData()
	data["user_prefix"] = strings.Repeat("a", 26)
	data["realm"] = "pve"

	resp, err := writeRole(ctx, b, storage, strings.Repeat("b", 25), data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.IsError() {
		t.Error("expected error response when userid would exceed 64 chars")
	}
}

// ── Group existence check (DR-2) ──────────────────────────────────────────────

// TestRoleWrite_GroupNotFound_Rejected verifies that when GetGroup returns
// ErrGroupNotFound (HTTP 500 + body "does not exist"), the role write
// is rejected with a clear error. This tests DR-2 specifically.
func TestRoleWrite_GroupNotFound_Rejected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	b, storage := setupBackendWithConfig(t, func(mc *pveapi.MockClient) {
		// Groups map is set but "vault-vm-admins" is not in it → GetGroup returns ErrGroupNotFound.
		mc.Groups = map[string]bool{
			// group is absent — GetGroup will return ErrGroupNotFound.
		}
	})

	resp, err := writeRole(ctx, b, storage, "myrole", validRoleData())
	if err != nil {
		t.Fatalf("unexpected framework error: %v", err)
	}
	if !resp.IsError() {
		t.Fatal("expected error response when group does not exist")
	}
	if !strings.Contains(strings.ToLower(resp.Error().Error()), "does not exist") {
		t.Errorf("expected error to mention 'does not exist'; got: %q", resp.Error())
	}
}

// TestRoleWrite_GroupNotFound_UsesErrGroupNotFound verifies that the mock
// uses ErrGroupNotFound (not ErrNotFound/ErrUserNotFound) for missing groups.
// This is the DR-2 sentinel test.
//
// The real invariant being tested here is that roleWrite returns a clear
// user-facing rejection (covered by TestRoleWrite_GroupNotFound_Rejected) and
// that the sentinel used for the GetGroup error path is ErrGroupNotFound,
// which is DISTINCT from ErrUserNotFound. The sentinel-distinctness property
// (errors.Is(ErrGroupNotFound, ErrNotFound) must be FALSE) lives in
// internal/pveapi/errors_test.go as TestSentinelDistinctness.
//
// This test is kept to document that the GetGroupFn injection hook still
// routes through the ErrGroupNotFound branch in roleWrite (not a generic
// internal error).
func TestRoleWrite_GroupNotFound_UsesErrGroupNotFound(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	b, storage := setupBackendWithConfig(t, func(mc *pveapi.MockClient) {
		mc.GetGroupFn = func(_ context.Context, group string) error {
			return pveapi.ErrGroupNotFound
		}
	})

	resp, err := writeRole(ctx, b, storage, "myrole", validRoleData())
	if err != nil {
		t.Fatalf("unexpected framework error: %v", err)
	}
	if !resp.IsError() {
		t.Fatal("expected error response when group does not exist")
	}
	// The error response must mention "does not exist" (user-facing message check).
	if !strings.Contains(strings.ToLower(resp.Error().Error()), "does not exist") {
		t.Errorf("expected error to mention 'does not exist'; got: %q", resp.Error())
	}
}

// ── Realm.AllocateUser check ──────────────────────────────────────────────────

func TestRoleWrite_MissingRealmAllocateUser_Rejected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	b, storage := setupBackendWithConfig(t, func(mc *pveapi.MockClient) {
		// Permissions tree lacks Realm.AllocateUser at /access/realm/pve.
		mc.GetPermissionsResult = pveapi.PermissionTree{
			"/access/groups": {
				"User.Modify": 1,
				"Sys.Audit":   1,
			},
			"/access/groups/vault-vm-admins": {
				"User.Modify": 1,
			},
			// NO Realm.AllocateUser entry.
		}
	})

	resp, err := writeRole(ctx, b, storage, "myrole", validRoleData())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.IsError() {
		t.Error("expected error response for missing Realm.AllocateUser")
	}
	if !strings.Contains(resp.Error().Error(), "Realm.AllocateUser") {
		t.Errorf("error should mention Realm.AllocateUser; got: %q", resp.Error())
	}
}

func TestRoleWrite_RealmAllocateUserAtAncestor_Accepted(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	b, storage := setupBackendWithConfig(t, func(mc *pveapi.MockClient) {
		// Realm.AllocateUser at ancestor "/access" with propagate=1 satisfies
		// /access/realm/pve.
		mc.GetPermissionsResult = pveapi.PermissionTree{
			"/access": {
				"Realm.AllocateUser": 1,
			},
			"/access/groups": {
				"User.Modify": 1,
				"Sys.Audit":   1,
			},
			"/access/groups/vault-vm-admins": {
				"User.Modify": 1,
			},
		}
	})

	resp, err := writeRole(ctx, b, storage, "myrole", validRoleData())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error: %s", resp.Error())
	}
}

// ── Per-group-path User.Modify propagate=0 detection ─────────────────────────

// TestRoleWrite_PerGroupUserModifyPropagate0_Rejected verifies that when the
// permissions tree shows User.Modify at /access/groups (parent) but NOT at
// /access/groups/<group>, role write is rejected.
//
// This catches the --propagate 0 misconfiguration: a propagate=0 grant at
// /access/groups passes the parent-level check but fails the per-group-path
// check that PVE enforces at user creation time.
func TestRoleWrite_PerGroupUserModifyPropagate0_Rejected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	b, storage := setupBackendWithConfig(t, func(mc *pveapi.MockClient) {
		// User.Modify only at parent /access/groups with propagate=1, but NO entry at
		// the per-group path /access/groups/vault-vm-admins.
		// HasPrivilege at /access/groups/vault-vm-admins checks the ancestor
		// /access/groups (propagate=1) — this SHOULD pass.
		// To simulate propagate=0 (the broken case), set propagate=0 at the parent
		// so it doesn't propagate to the per-group path.
		mc.GetPermissionsResult = pveapi.PermissionTree{
			"/access/groups": {
				"User.Modify": 0, // propagate=0 → does NOT propagate to /access/groups/<group>
				"Sys.Audit":   1,
			},
			"/access/realm/pve": {
				"Realm.AllocateUser": 1,
			},
		}
	})

	resp, err := writeRole(ctx, b, storage, "myrole", validRoleData())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.IsError() {
		t.Error("expected error response: propagate=0 at parent should NOT satisfy per-group-path check")
	}
	if !strings.Contains(strings.ToLower(resp.Error().Error()), "user.modify") {
		t.Errorf("error should mention User.Modify; got: %q", resp.Error())
	}
}

// TestRoleWrite_PerGroupUserModifyExactPath_Accepted verifies that User.Modify
// at the exact per-group path /access/groups/<group> (any propagate flag)
// satisfies the check.
func TestRoleWrite_PerGroupUserModifyExactPath_Accepted(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	b, storage := setupBackendWithConfig(t, func(mc *pveapi.MockClient) {
		// User.Modify at parent with propagate=0 (would fail ancestor check),
		// BUT also at the exact per-group path — exact path satisfies regardless.
		mc.GetPermissionsResult = pveapi.PermissionTree{
			"/access/groups": {
				"User.Modify": 0, // propagate=0 — does NOT propagate
				"Sys.Audit":   1,
			},
			"/access/groups/vault-vm-admins": {
				"User.Modify": 0, // exact path — propagate flag irrelevant for exact match
			},
			"/access/realm/pve": {
				"Realm.AllocateUser": 1,
			},
		}
	})

	resp, err := writeRole(ctx, b, storage, "myrole", validRoleData())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error: %s", resp.Error())
	}
}

// TestRoleWrite_PropagatingParentSatisfiesPerGroupPath verifies that when
// User.Modify is at /access/groups with propagate=1, HasPrivilege at
// /access/groups/<group> is satisfied (the normal, well-configured case).
func TestRoleWrite_PropagatingParentSatisfiesPerGroupPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	b, storage := setupBackendWithConfig(t, func(mc *pveapi.MockClient) {
		mc.GetPermissionsResult = pveapi.PermissionTree{
			"/access/groups": {
				"User.Modify": 1, // propagate=1 — propagates to /access/groups/*
				"Sys.Audit":   1,
			},
			"/access/realm/pve": {
				"Realm.AllocateUser": 1,
			},
		}
	})

	resp, err := writeRole(ctx, b, storage, "myrole", validRoleData())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("unexpected error (propagating parent should satisfy per-group path): %s", resp.Error())
	}
}

// ── GetPermissions 403 handling ───────────────────────────────────────────────

func TestRoleWrite_GetPermissions403_Rejected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	b, storage := setupBackendWithConfig(t, func(mc *pveapi.MockClient) {
		mc.GetPermissionsFn = func(_ context.Context) (pveapi.PermissionTree, error) {
			return nil, pveapi.ErrForbidden
		}
	})

	resp, err := writeRole(ctx, b, storage, "myrole", validRoleData())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.IsError() {
		t.Error("expected error response when GetPermissions returns 403")
	}
}

// ── No config check ───────────────────────────────────────────────────────────

func TestRoleWrite_NoConfig_Rejected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Don't write a config — role write should fail.
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := newBackend(ctx, config)
	if err != nil {
		t.Fatalf("newBackend: %v", err)
	}
	mc := &pveapi.MockClient{}
	b.newClient = func(_ *proxmoxConfig) (pveapi.Client, error) { return mc, nil }

	resp, writeErr := writeRole(ctx, b, config.StorageView, "myrole", validRoleData())
	if writeErr != nil {
		t.Fatalf("unexpected framework error: %v", writeErr)
	}
	if !resp.IsError() {
		t.Error("expected error response when no config is present")
	}
}

// ── ttls() fallback chain ─────────────────────────────────────────────────────

// TestTTLsFallback_BothUnset verifies that when both role.TTL and role.MaxTTL
// are 0 (unset), and config defaults are also 0 (unset), ttls() returns (0, 0).
// This is the "both unset" case — CalculateTTL will resolve to system defaults.
// The issuance path then refuses if the result is truly 0 (unlimited).
func TestTTLsFallback_BothUnset(t *testing.T) {
	t.Parallel()

	role := &proxmoxRole{TTL: 0, MaxTTL: 0}
	cfg := &proxmoxConfig{DefaultTTL: 0, DefaultMaxTTL: 0}

	ttl, maxTTL := role.ttls(cfg)
	if ttl != 0 {
		t.Errorf("ttl = %v; want 0 (unset for CalculateTTL to resolve)", ttl)
	}
	if maxTTL != 0 {
		t.Errorf("maxTTL = %v; want 0 (unset for CalculateTTL to resolve)", maxTTL)
	}
}

// TestTTLsFallback_RoleSetIgnoresConfigDefault verifies that when role.TTL
// is set, config.DefaultTTL is NOT used.
func TestTTLsFallback_RoleSetIgnoresConfigDefault(t *testing.T) {
	t.Parallel()

	role := &proxmoxRole{TTL: 1800, MaxTTL: 0}
	cfg := &proxmoxConfig{DefaultTTL: 3600, DefaultMaxTTL: 86400}

	ttl, maxTTL := role.ttls(cfg)
	if ttl != 1800*time.Second {
		t.Errorf("ttl = %v; want 1800s (role value, not config default)", ttl)
	}
	// maxTTL: role.MaxTTL=0 → falls back to config.DefaultMaxTTL=86400
	if maxTTL != 86400*time.Second {
		t.Errorf("maxTTL = %v; want 86400s (config default fallback)", maxTTL)
	}
}

// TestTTLsFallback_ConfigDefaultUsedWhenRoleUnset verifies that when role.TTL
// is 0 (unset), config.DefaultTTL is used as the fallback.
func TestTTLsFallback_ConfigDefaultUsedWhenRoleUnset(t *testing.T) {
	t.Parallel()

	role := &proxmoxRole{TTL: 0, MaxTTL: 0}
	cfg := &proxmoxConfig{DefaultTTL: 7200, DefaultMaxTTL: 43200}

	ttl, maxTTL := role.ttls(cfg)
	if ttl != 7200*time.Second {
		t.Errorf("ttl = %v; want 7200s (config default)", ttl)
	}
	if maxTTL != 43200*time.Second {
		t.Errorf("maxTTL = %v; want 43200s (config default)", maxTTL)
	}
}

// TestTTLsFallback_RoleMaxTTLSet verifies that when role.MaxTTL is set,
// config.DefaultMaxTTL is NOT used (role value wins).
func TestTTLsFallback_RoleMaxTTLSet(t *testing.T) {
	t.Parallel()

	role := &proxmoxRole{TTL: 0, MaxTTL: 3600}
	cfg := &proxmoxConfig{DefaultTTL: 1800, DefaultMaxTTL: 86400}

	ttl, maxTTL := role.ttls(cfg)
	// TTL: role.TTL=0 → config.DefaultTTL=1800
	if ttl != 1800*time.Second {
		t.Errorf("ttl = %v; want 1800s", ttl)
	}
	// MaxTTL: role.MaxTTL=3600 (not 0) → use role value, not config
	if maxTTL != 3600*time.Second {
		t.Errorf("maxTTL = %v; want 3600s (role value)", maxTTL)
	}
}

// TestTTLsFallback_ConfigIsNotACap verifies the critical property:
// config.default_ttl is a FALLBACK, NOT a cap. When role.TTL > config.DefaultTTL,
// the role value is used (not capped to config.DefaultTTL).
func TestTTLsFallback_ConfigIsNotACap(t *testing.T) {
	t.Parallel()

	// role.TTL = 7200, config.DefaultTTL = 3600.
	// A naive min() would return 3600 — that would be WRONG.
	// Correct fallback: role.TTL is set, so config.DefaultTTL is ignored entirely.
	role := &proxmoxRole{TTL: 7200, MaxTTL: 0}
	cfg := &proxmoxConfig{DefaultTTL: 3600, DefaultMaxTTL: 0}

	ttl, _ := role.ttls(cfg)
	if ttl != 7200*time.Second {
		t.Errorf("ttl = %v; want 7200s (config.default_ttl must NOT cap the role ttl)", ttl)
	}
}

// ── cappedMaxTTL 4-case ───────────────────────────────────────────────────────

// TestCappedMaxTTL_RoleUnset_ReturnsSysMax verifies case (0, sysMax) → sysMax.
func TestCappedMaxTTL_RoleUnset_ReturnsSysMax(t *testing.T) {
	t.Parallel()

	sysMax := 24 * time.Hour
	got := cappedMaxTTL(0, sysMax)
	if got != sysMax {
		t.Errorf("cappedMaxTTL(0, %v) = %v; want %v", sysMax, got, sysMax)
	}
}

// TestCappedMaxTTL_SysMaxUnset_ReturnsRoleMax verifies case (roleMax, 0) → roleMax.
func TestCappedMaxTTL_SysMaxUnset_ReturnsRoleMax(t *testing.T) {
	t.Parallel()

	roleMax := 12 * time.Hour
	got := cappedMaxTTL(roleMax, 0)
	if got != roleMax {
		t.Errorf("cappedMaxTTL(%v, 0) = %v; want %v", roleMax, got, roleMax)
	}
}

// TestCappedMaxTTL_BothUnset_ReturnsZero verifies case (0, 0) → 0.
func TestCappedMaxTTL_BothUnset_ReturnsZero(t *testing.T) {
	t.Parallel()

	got := cappedMaxTTL(0, 0)
	if got != 0 {
		t.Errorf("cappedMaxTTL(0, 0) = %v; want 0", got)
	}
}

// TestCappedMaxTTL_BothSet_ReturnsMin verifies case (A, B) → min(A, B).
func TestCappedMaxTTL_BothSet_ReturnsMin(t *testing.T) {
	t.Parallel()

	tests := []struct {
		roleMax time.Duration
		sysMax  time.Duration
		want    time.Duration
	}{
		{3 * time.Hour, 24 * time.Hour, 3 * time.Hour},
		{24 * time.Hour, 3 * time.Hour, 3 * time.Hour},
		{6 * time.Hour, 6 * time.Hour, 6 * time.Hour},
	}
	for _, tc := range tests {
		got := cappedMaxTTL(tc.roleMax, tc.sysMax)
		if got != tc.want {
			t.Errorf("cappedMaxTTL(%v, %v) = %v; want %v", tc.roleMax, tc.sysMax, got, tc.want)
		}
	}
}

// ── Round-trip test ───────────────────────────────────────────────────────────

func TestRoleWriteReadDeleteRoundTrip(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	b, storage := setupBackendWithConfig(t, func(mc *pveapi.MockClient) {
		mc.GetPermissionsResult = fullPermTree("vault-vm-admins")
	})

	data := map[string]interface{}{
		"group":       "vault-vm-admins",
		"user_prefix": "myprefix",
		"realm":       "pve",
		"ttl":         1800,
		"max_ttl":     7200,
	}

	// Write.
	if resp, err := writeRole(ctx, b, storage, "testrole", data); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("write: err=%v resp=%v", err, resp)
	}

	// Read back and verify.
	resp, err := readRole(ctx, b, storage, "testrole")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if resp == nil {
		t.Fatal("nil read response after write")
	}
	if resp.Data["user_prefix"] != "myprefix" {
		t.Errorf("user_prefix = %v; want myprefix", resp.Data["user_prefix"])
	}
	if resp.Data["ttl"] != 1800 {
		t.Errorf("ttl = %v; want 1800", resp.Data["ttl"])
	}
	if resp.Data["max_ttl"] != 7200 {
		t.Errorf("max_ttl = %v; want 7200", resp.Data["max_ttl"])
	}

	// Delete.
	if _, err := deleteRole(ctx, b, storage, "testrole"); err != nil {
		t.Fatalf("delete: %v", err)
	}

	// Read after delete → nil.
	readResp, err := readRole(ctx, b, storage, "testrole")
	if err != nil {
		t.Fatalf("read after delete: %v", err)
	}
	if readResp != nil {
		t.Error("expected nil response after delete")
	}
}

// ── Partial-update test ───────────────────────────────────────────────────────

// TestRoleWrite_PartialUpdate verifies that an UpdateOperation only overwrites
// the fields explicitly present in the request body. Fields absent from the
// update request must retain their original stored values and must NOT be
// silently reset to schema defaults.
//
// Scenario: create a role with non-default user_prefix, realm, and max_ttl;
// then update with only ttl set. The untouched fields (user_prefix, max_ttl,
// realm) must survive the update unchanged.
func TestRoleWrite_PartialUpdate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	b, storage := setupBackendWithConfig(t, func(mc *pveapi.MockClient) {
		mc.Groups = map[string]bool{
			"vault-vm-admins": true,
		}
		mc.GetPermissionsResult = fullPermTree("vault-vm-admins")
	})

	// Step 1: create with non-default user_prefix and max_ttl.
	createData := map[string]interface{}{
		"group":       "vault-vm-admins",
		"user_prefix": "myengine", // non-default (schema default is "vault")
		"realm":       "pve",
		"ttl":         900,
		"max_ttl":     7200, // non-default (schema default is 0 = unset)
	}
	resp, err := writeRole(ctx, b, storage, "testrole", createData)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("create error: %s", resp.Error())
	}

	// Step 2: partial update — only change ttl; leave user_prefix/realm/max_ttl
	// absent from the request. On a correct merge-on-update implementation these
	// must retain their original values; on a broken d.Get implementation they
	// would be silently reset to schema defaults ("vault", 0, "pve").
	updateData := map[string]interface{}{
		// group must be present so PVE validation (GetGroup, GetPermissions) can proceed.
		"group": "vault-vm-admins",
		"ttl":   1800,
		// user_prefix, realm, max_ttl intentionally omitted.
	}
	resp, err = updateRole(ctx, b, storage, "testrole", updateData)
	if err != nil {
		t.Fatalf("partial update: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("partial update error: %s", resp.Error())
	}

	// Step 3: read back and assert that untouched fields retained their original values.
	readResp, err := readRole(ctx, b, storage, "testrole")
	if err != nil {
		t.Fatalf("read after partial update: %v", err)
	}
	if readResp == nil {
		t.Fatal("expected non-nil read response after update")
	}

	// ttl SHOULD have been updated.
	if readResp.Data["ttl"] != 1800 {
		t.Errorf("ttl = %v; want 1800 (should be updated)", readResp.Data["ttl"])
	}

	// user_prefix must NOT be reset to the schema default "vault".
	if readResp.Data["user_prefix"] != "myengine" {
		t.Errorf("user_prefix = %v; want myengine (must retain original, not reset to default 'vault')",
			readResp.Data["user_prefix"])
	}

	// max_ttl must NOT be reset to 0 (schema default for unset TypeDurationSecond).
	if readResp.Data["max_ttl"] != 7200 {
		t.Errorf("max_ttl = %v; want 7200 (must retain original, not reset to 0)",
			readResp.Data["max_ttl"])
	}

	// realm must be retained as "pve".
	if readResp.Data["realm"] != "pve" {
		t.Errorf("realm = %v; want pve (must retain original)", readResp.Data["realm"])
	}
}
