// Package proxmox — unit tests for secret_token.go.
//
// Covers secretTokenRenew and secretTokenRevoke with a mocked PVE API client.
// Mirrors path_creds_test.go and wal_test.go conventions exactly.
//
// Test coverage:
//   - Renew happy path: InternalData decoded, pre-update GetUser (enabled), UpdateUser
//     called with correct args (+expireGraceSecs expire grace, Groups, Enable=true, Append=true),
//     post-update GetUser group read-back, returns renewed Secret with TTL>0.
//   - Renew refuses when pre-update GetUser returns Enable==false (disabled user):
//     UpdateUser must NOT be called.
//   - Renew group read-back assertion failure (post-update GetUser lacks group): error.
//   - Renew effective_max_ttl float64 round-trip: JSON-decoded float64 decodes correctly.
//   - Renew refuses when TTL collapses to <=0 (past max): error, no PVE calls.
//   - Renew errors on missing/invalid InternalData keys.
//   - Renew with role_name pointing to existing role honors role.ttl.
//   - Renew with role_name pointing to deleted role falls back gracefully (no hard fail).
//   - Renew with multiple groups warns but does not fail.
//   - Revoke happy path: DeleteUser called, returns (nil,nil).
//   - Revoke idempotent: ErrUserNotFound → (nil,nil).
//   - Revoke transient error: other error returned wrapped.
package proxmox

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	pveapi "github.com/hazmei/vault-plugin-secrets-proxmox/internal/pveapi"
)

// ── Helpers ──────────────────────────────────────────────────────────────────

// makeRenewRequest builds a logical.Request for a renew operation with the
// given InternalData. The Secret is pre-populated with IssueTime=now (for
// CalculateTTL) and a positive TTL/MaxTTL so the framework sees it as valid.
// req.Storage is set to the provided storage so that secretTokenRenew can
// call getRole/getConfig without the caller having to set it again.
func makeRenewRequest(storage logical.Storage, internalData map[string]interface{}, issueTime time.Time, increment time.Duration) *logical.Request {
	s := &logical.Secret{
		InternalData: internalData,
	}
	s.IssueTime = issueTime
	s.Increment = increment
	s.TTL = 3600 * time.Second
	s.MaxTTL = 86400 * time.Second
	s.Renewable = true
	req := logical.RenewRequest("creds/myrole", s, nil)
	req.Storage = storage
	return req
}

// makeRevokeRequest builds a logical.Request for a revoke operation with the
// given InternalData. req.Storage is set to the provided storage.
func makeRevokeRequest(storage logical.Storage, internalData map[string]interface{}) *logical.Request {
	s := &logical.Secret{
		InternalData: internalData,
	}
	req := logical.RevokeRequest("creds/myrole", s, nil)
	req.Storage = storage
	return req
}

// standardRenewInternalData returns valid InternalData for a renew request,
// with effective_max_ttl stored as int64 (the issuance path writes int64).
// role_name and expire are included per the documented 5-field InternalData schema.
func standardRenewInternalData(effectiveMaxTTL time.Duration) map[string]interface{} {
	return map[string]interface{}{
		"pve_userid":        "vault-myrole-abc12345@pve",
		"group":             "vault-vm-admins",
		"effective_max_ttl": int64(effectiveMaxTTL),
		"role_name":         "",                                     // empty — role lookup returns nil → lease-TTL fallback
		"expire":            time.Now().Add(effectiveMaxTTL).Unix(), // placeholder
	}
}

// setupBackendForRenew creates a backend with config written. The mock is
// pre-seeded with the given user so GetUser and UpdateUser work by default.
// Additional mock customisation via extraSetup.
func setupBackendForRenew(t *testing.T, userid, group string, userEnabled bool, extraSetup func(*pveapi.MockClient)) (*backend, logical.Storage) {
	t.Helper()
	ctx := context.Background()

	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		mc.Users = map[string]pveapi.UserInfo{
			userid: {
				Groups: []string{group},
				Enable: userEnabled,
				Expire: time.Now().Add(2 * time.Hour).Unix(),
			},
		}
		if extraSetup != nil {
			extraSetup(mc)
		}
	})

	if _, err := writeConfig(ctx, b, storage, validConfigData()); err != nil {
		t.Fatalf("setupBackendForRenew: writeConfig: %v", err)
	}
	return b, storage
}

// ── secretTokenRenew tests ───────────────────────────────────────────────────

// TestSecretTokenRenew_HappyPath verifies the full happy-path renewal:
//   - pre-update GetUser is called (user is enabled).
//   - UpdateUser is called with Expire ≥ now+ttl+expireGraceSecs, Groups=group, Enable=true, Append=true.
//   - post-update GetUser group read-back succeeds.
//   - Returns non-nil Secret with TTL>0, MaxTTL==effectiveMaxTTL, Renewable.
func TestSecretTokenRenew_HappyPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	const (
		userid          = "vault-myrole-abc12345@pve"
		group           = "vault-vm-admins"
		effectiveMaxTTL = 86400 * time.Second
		renewIncrement  = 3600 * time.Second
	)

	var capturedUpdateReq pveapi.UpdateUserRequest
	getCallCount := 0

	b, storage := setupBackendForRenew(t, userid, group, true, func(mc *pveapi.MockClient) {
		// Track GetUser call count and provide correct user state on each call.
		mc.GetUserFn = func(_ context.Context, uid string) (pveapi.UserInfo, error) {
			getCallCount++
			return pveapi.UserInfo{
				Groups: []string{group},
				Enable: true,
				Expire: time.Now().Add(2 * time.Hour).Unix(),
			}, nil
		}
		mc.UpdateUserFn = func(_ context.Context, req pveapi.UpdateUserRequest) error {
			capturedUpdateReq = req
			return nil
		}
	})

	before := time.Now()
	internalData := standardRenewInternalData(effectiveMaxTTL)
	req := makeRenewRequest(storage, internalData, time.Now().Add(-30*time.Minute), renewIncrement)

	resp, err := b.secretTokenRenew(ctx, req, nil)
	after := time.Now()
	if err != nil {
		t.Fatalf("secretTokenRenew: unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
		return
	}
	if resp.Secret == nil {
		t.Fatal("expected non-nil Secret in renewal response")
	}

	// TTL must be positive.
	if resp.Secret.TTL <= 0 {
		t.Errorf("resp.Secret.TTL = %v; want > 0", resp.Secret.TTL)
	}

	// MaxTTL must equal effectiveMaxTTL.
	if resp.Secret.MaxTTL != effectiveMaxTTL {
		t.Errorf("resp.Secret.MaxTTL = %v; want %v", resp.Secret.MaxTTL, effectiveMaxTTL)
	}

	// Renewable must be true.
	if !resp.Secret.Renewable {
		t.Error("resp.Secret.Renewable must be true")
	}

	// UpdateUser must have been called.
	if capturedUpdateReq.UserID == "" {
		t.Fatal("UpdateUser was not called")
	}
	if capturedUpdateReq.UserID != userid {
		t.Errorf("UpdateUser UserID = %q; want %q", capturedUpdateReq.UserID, userid)
	}
	if capturedUpdateReq.Groups != group {
		t.Errorf("UpdateUser Groups = %q; want %q", capturedUpdateReq.Groups, group)
	}
	if !capturedUpdateReq.Enable {
		t.Error("UpdateUser Enable must be true")
	}
	if !capturedUpdateReq.Append {
		t.Error("UpdateUser Append must be true (MANDATORY)")
	}

	// Expire grace: expire must be ≥ before+TTL+expireGraceSecs.
	minExpire := before.Add(resp.Secret.TTL + expireGraceSecs*time.Second).Unix()
	maxExpire := after.Add(resp.Secret.TTL + (expireGraceSecs+1)*time.Second).Unix()
	if capturedUpdateReq.Expire < minExpire || capturedUpdateReq.Expire > maxExpire {
		t.Errorf("UpdateUser Expire = %d; expected in [%d, %d] (now+TTL+%ds grace)",
			capturedUpdateReq.Expire, minExpire, maxExpire, expireGraceSecs)
	}

	// Both a pre-update GetUser and a post-update GetUser must have been called (2 total).
	if getCallCount < 2 {
		t.Errorf("GetUser call count = %d; want ≥ 2 (pre-update + post-update)", getCallCount)
	}

	// InternalData["expire"] must have been rewritten to the new expire value.
	if storedExpire, ok := resp.Secret.InternalData["expire"].(int64); !ok || storedExpire != capturedUpdateReq.Expire {
		t.Errorf("InternalData expire = %v; want %d (newExpire from this renewal)", resp.Secret.InternalData["expire"], capturedUpdateReq.Expire)
	}
}

// TestSecretTokenRenew_DisabledUser_RefusesRenewal verifies that if the pre-update
// GetUser returns Enable==false, renewal is refused and UpdateUser is NOT called.
// This guards against re-enabling a user that an operator deliberately disabled
// for incident response.
func TestSecretTokenRenew_DisabledUser_RefusesRenewal(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	const (
		userid          = "vault-myrole-disabled123@pve"
		group           = "vault-vm-admins"
		effectiveMaxTTL = 86400 * time.Second
	)

	updateCalled := false
	b, storage := setupBackendForRenew(t, userid, group, false /* disabled */, func(mc *pveapi.MockClient) {
		// GetUser returns a DISABLED user.
		mc.GetUserFn = func(_ context.Context, uid string) (pveapi.UserInfo, error) {
			return pveapi.UserInfo{
				Groups: []string{group},
				Enable: false, // operator-disabled
				Expire: time.Now().Add(2 * time.Hour).Unix(),
			}, nil
		}
		mc.UpdateUserFn = func(_ context.Context, req pveapi.UpdateUserRequest) error {
			updateCalled = true
			return nil
		}
	})

	internalData := standardRenewInternalData(effectiveMaxTTL)
	req := makeRenewRequest(storage, internalData, time.Now().Add(-30*time.Minute), 3600*time.Second)

	resp, err := b.secretTokenRenew(ctx, req, nil)
	// Must fail.
	if err == nil {
		t.Fatal("expected error when user is disabled; got nil")
		return
	}
	if resp != nil && resp.Secret != nil {
		t.Error("resp.Secret must be nil when renewal is refused")
	}

	// UpdateUser must NOT have been called.
	if updateCalled {
		t.Error("UpdateUser must NOT be called when user is disabled; renewal refused before update")
	}

	// Error message must mention disabled/re-enable/incident.
	errMsg := strings.ToLower(err.Error())
	if !strings.Contains(errMsg, "disabled") {
		t.Errorf("error should mention 'disabled'; got: %q", err.Error())
	}
}

// TestSecretTokenRenew_GroupReadbackFails verifies that if the post-update GetUser
// does not include the expected group, renewal returns an error.
func TestSecretTokenRenew_GroupReadbackFails(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	const (
		userid          = "vault-myrole-readback456@pve"
		group           = "vault-vm-admins"
		effectiveMaxTTL = 86400 * time.Second
	)

	getCallCount := 0
	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		// pre-update GetUser: user is enabled.
		// post-update GetUser: group is MISSING (simulates PVE silent drop).
		mc.GetUserFn = func(_ context.Context, _ string) (pveapi.UserInfo, error) {
			getCallCount++
			if getCallCount == 1 {
				return pveapi.UserInfo{Groups: []string{group}, Enable: true}, nil
			}
			return pveapi.UserInfo{Groups: []string{}, Enable: true}, nil
		}
		// UpdateUser must succeed (use a no-op Fn so it doesn't need mc.Users).
		mc.UpdateUserFn = func(_ context.Context, _ pveapi.UpdateUserRequest) error {
			return nil
		}
	})
	if _, err := writeConfig(ctx, b, storage, validConfigData()); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}

	internalData := standardRenewInternalData(effectiveMaxTTL)
	req := makeRenewRequest(storage, internalData, time.Now().Add(-30*time.Minute), 3600*time.Second)

	_, err := b.secretTokenRenew(ctx, req, nil)
	if err == nil {
		t.Fatal("expected error when group read-back fails; got nil")
		return
	}
	errMsg := strings.ToLower(err.Error())
	if !strings.Contains(errMsg, "group") {
		t.Errorf("error should mention 'group'; got: %q", err.Error())
	}
}

// TestSecretTokenRenew_Float64EffectiveMaxTTL verifies that effective_max_ttl
// arriving as float64 (JSON round-trip decodes int64 as float64) is decoded
// correctly by extractLeaseInternalData. This exercises the float64 case.
func TestSecretTokenRenew_Float64EffectiveMaxTTL(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	const (
		userid          = "vault-myrole-floatttl789@pve"
		group           = "vault-vm-admins"
		effectiveMaxTTL = 86400 * time.Second
	)

	b, storage := setupBackendForRenew(t, userid, group, true, nil)

	// Simulate JSON round-trip: int64 → float64.
	internalData := map[string]interface{}{
		"pve_userid":        userid,
		"group":             group,
		"effective_max_ttl": float64(int64(effectiveMaxTTL)), // float64, as JSON decodes it
	}
	req := makeRenewRequest(storage, internalData, time.Now().Add(-30*time.Minute), 3600*time.Second)

	resp, err := b.secretTokenRenew(ctx, req, nil)
	if err != nil {
		t.Fatalf("secretTokenRenew with float64 effective_max_ttl: unexpected error: %v", err)
	}
	if resp == nil || resp.Secret == nil {
		t.Fatal("expected non-nil Secret")
	}
	if resp.Secret.TTL <= 0 {
		t.Errorf("resp.Secret.TTL = %v; want > 0", resp.Secret.TTL)
	}
	if resp.Secret.MaxTTL != effectiveMaxTTL {
		t.Errorf("resp.Secret.MaxTTL = %v; want %v (float64 round-trip must be lossless)",
			resp.Secret.MaxTTL, effectiveMaxTTL)
	}
}

// TestSecretTokenRenew_TTLPastMax verifies that renewal is refused when the
// effective TTL collapses to ≤0 (past max). This is achieved by setting
// IssueTime far enough in the past that IssueTime + effectiveMaxTTL < now.
// Also asserts that no PVE (GetUser/UpdateUser) calls are made before the refusal.
func TestSecretTokenRenew_TTLPastMax(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	const (
		userid          = "vault-myrole-pastmax999@pve"
		group           = "vault-vm-admins"
		effectiveMaxTTL = 1 * time.Hour // very short max
	)

	getUserCallCount := 0
	updateUserCallCount := 0
	b, storage := setupBackendForRenew(t, userid, group, true, func(mc *pveapi.MockClient) {
		mc.GetUserFn = func(_ context.Context, _ string) (pveapi.UserInfo, error) {
			getUserCallCount++
			return pveapi.UserInfo{Groups: []string{group}, Enable: true}, nil
		}
		mc.UpdateUserFn = func(_ context.Context, _ pveapi.UpdateUserRequest) error {
			updateUserCallCount++
			return nil
		}
	})

	internalData := standardRenewInternalData(effectiveMaxTTL)
	// IssueTime was 2 hours ago; effectiveMaxTTL is 1h → TTL must be 0 or negative.
	req := makeRenewRequest(storage, internalData, time.Now().Add(-2*time.Hour), 3600*time.Second)

	_, err := b.secretTokenRenew(ctx, req, nil)
	if err == nil {
		t.Fatal("expected error when TTL is past max; got nil")
		return
	}
	errMsg := strings.ToLower(err.Error())
	if !strings.Contains(errMsg, "ttl") && !strings.Contains(errMsg, "zero") && !strings.Contains(errMsg, "max") {
		t.Errorf("error should mention TTL/zero/max; got: %q", err.Error())
	}

	// No PVE calls (GetUser/UpdateUser) must have been made — the TTL refusal
	// must happen before any PVE interaction. Storage reads (getRole/getConfig) are
	// not PVE calls and are allowed before the TTL check.
	if getUserCallCount != 0 {
		t.Errorf("GetUser was called %d times; want 0 (TTL refusal must precede PVE calls)", getUserCallCount)
	}
	if updateUserCallCount != 0 {
		t.Errorf("UpdateUser was called %d times; want 0 (TTL refusal must precede PVE calls)", updateUserCallCount)
	}
}

// TestSecretTokenRenew_MissingPveUserid verifies that missing pve_userid in
// InternalData returns an error immediately.
func TestSecretTokenRenew_MissingPveUserid(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	b, storage := newTestBackend(t, defaultMock())
	if _, err := writeConfig(ctx, b, storage, validConfigData()); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}

	internalData := map[string]interface{}{
		// pve_userid intentionally omitted
		"group":             "vault-vm-admins",
		"effective_max_ttl": int64(86400 * time.Second),
	}
	req := makeRenewRequest(storage, internalData, time.Now(), 3600*time.Second)

	_, err := b.secretTokenRenew(ctx, req, nil)
	if err == nil {
		t.Fatal("expected error for missing pve_userid; got nil")
		return
	}
	if !strings.Contains(strings.ToLower(err.Error()), "pve_userid") {
		t.Errorf("error should mention pve_userid; got: %q", err.Error())
	}
}

// TestSecretTokenRenew_MissingGroup verifies that missing group in InternalData
// returns an error.
func TestSecretTokenRenew_MissingGroup(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	b, storage := newTestBackend(t, defaultMock())
	if _, err := writeConfig(ctx, b, storage, validConfigData()); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}

	internalData := map[string]interface{}{
		"pve_userid": "vault-myrole-abc12345@pve",
		// group intentionally omitted
		"effective_max_ttl": int64(86400 * time.Second),
	}
	req := makeRenewRequest(storage, internalData, time.Now(), 3600*time.Second)

	_, err := b.secretTokenRenew(ctx, req, nil)
	if err == nil {
		t.Fatal("expected error for missing group; got nil")
		return
	}
	if !strings.Contains(strings.ToLower(err.Error()), "group") {
		t.Errorf("error should mention group; got: %q", err.Error())
	}
}

// TestSecretTokenRenew_MissingEffectiveMaxTTL verifies that missing
// effective_max_ttl in InternalData returns an error.
func TestSecretTokenRenew_MissingEffectiveMaxTTL(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	b, storage := newTestBackend(t, defaultMock())
	if _, err := writeConfig(ctx, b, storage, validConfigData()); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}

	internalData := map[string]interface{}{
		"pve_userid": "vault-myrole-abc12345@pve",
		"group":      "vault-vm-admins",
		// effective_max_ttl intentionally omitted
	}
	req := makeRenewRequest(storage, internalData, time.Now(), 3600*time.Second)

	_, err := b.secretTokenRenew(ctx, req, nil)
	if err == nil {
		t.Fatal("expected error for missing effective_max_ttl; got nil")
		return
	}
	if !strings.Contains(strings.ToLower(err.Error()), "effective_max_ttl") {
		t.Errorf("error should mention effective_max_ttl; got: %q", err.Error())
	}
}

// TestSecretTokenRenew_WrongTypeEffectiveMaxTTL verifies that an unexpected
// type (e.g. string) for effective_max_ttl returns an error.
func TestSecretTokenRenew_WrongTypeEffectiveMaxTTL(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	b, storage := newTestBackend(t, defaultMock())
	if _, err := writeConfig(ctx, b, storage, validConfigData()); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}

	internalData := map[string]interface{}{
		"pve_userid":        "vault-myrole-abc12345@pve",
		"group":             "vault-vm-admins",
		"effective_max_ttl": "not-a-number", // wrong type
	}
	req := makeRenewRequest(storage, internalData, time.Now(), 3600*time.Second)

	_, err := b.secretTokenRenew(ctx, req, nil)
	if err == nil {
		t.Fatal("expected error for wrong type effective_max_ttl; got nil")
		return
	}
}

// TestSecretTokenRenew_RoleNamePresent_HonorsRoleTTL verifies that when
// role_name in InternalData points to an existing role with a configured ttl,
// a no-increment renewal (increment=0) uses the role's ttl as the backendTTL
// rather than the system default of 0.
func TestSecretTokenRenew_RoleNamePresent_HonorsRoleTTL(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	const (
		userid          = "vault-myrole-rolettl001@pve"
		group           = "vault-vm-admins"
		effectiveMaxTTL = 86400 * time.Second
		roleTTL         = 3600 // seconds — the role's configured ttl
	)

	b, storage := setupBackendForRenew(t, userid, group, true, func(mc *pveapi.MockClient) {
		mc.GetPermissionsResult = pveapi.PermissionTree{
			"/access/groups":                 {"User.Modify": 1, "Sys.Audit": 1},
			"/access/groups/vault-vm-admins": {"User.Modify": 1},
			"/access/realm/pve":              {"Realm.AllocateUser": 1},
		}
		mc.Groups = map[string]bool{"vault-vm-admins": true}
	})

	// Write a role with a known ttl.
	roleData := map[string]interface{}{
		"group":       "vault-vm-admins",
		"user_prefix": "vault",
		"realm":       "pve",
		"ttl":         roleTTL,
		"max_ttl":     86400,
	}
	if _, err := writeRole(ctx, b, storage, "myrole", roleData); err != nil {
		t.Fatalf("writeRole: %v", err)
	}

	internalData := map[string]interface{}{
		"pve_userid":        userid,
		"group":             group,
		"effective_max_ttl": int64(effectiveMaxTTL),
		"role_name":         "myrole", // points to the role above
		"expire":            time.Now().Add(effectiveMaxTTL).Unix(),
	}
	// Use increment=0 so CalculateTTL falls back to backendTTL (= role.ttl).
	req := makeRenewRequest(storage, internalData, time.Now().Add(-30*time.Minute), 0)

	resp, err := b.secretTokenRenew(ctx, req, nil)
	if err != nil {
		t.Fatalf("secretTokenRenew: unexpected error: %v", err)
	}
	if resp == nil || resp.Secret == nil {
		t.Fatal("expected non-nil Secret")
	}
	// TTL must be approximately roleTTL (the role's configured backendTTL).
	// CalculateTTL with increment=0 and backendTTL=3600s yields ~3600s.
	if resp.Secret.TTL <= 0 {
		t.Errorf("resp.Secret.TTL = %v; want > 0", resp.Secret.TTL)
	}
	// Assert TTL is close to roleTTL (within 5s tolerance for test timing).
	want := time.Duration(roleTTL) * time.Second
	diff := resp.Secret.TTL - want
	if diff < 0 {
		diff = -diff
	}
	if diff > 5*time.Second {
		t.Errorf("resp.Secret.TTL = %v; want ~%v (role.ttl); diff=%v", resp.Secret.TTL, want, diff)
	}
}

// TestSecretTokenRenew_DeletedRole_FallsBackGracefully verifies that when
// role_name in InternalData points to a role that no longer exists, renewal
// still succeeds without a hard fail. This is the documented fallback behavior:
// missing role → backendTTL=0 → CalculateTTL uses increment from the renewal request.
func TestSecretTokenRenew_DeletedRole_FallsBackGracefully(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	const (
		userid          = "vault-myrole-delrole002@pve"
		group           = "vault-vm-admins"
		effectiveMaxTTL = 86400 * time.Second
	)

	b, storage := setupBackendForRenew(t, userid, group, true, nil)

	// Do NOT write a role named "deleted-role" — it should be absent.
	internalData := map[string]interface{}{
		"pve_userid":        userid,
		"group":             group,
		"effective_max_ttl": int64(effectiveMaxTTL),
		"role_name":         "deleted-role", // role does not exist in storage
		"expire":            time.Now().Add(effectiveMaxTTL).Unix(),
	}
	// Use a positive increment so the renewal can succeed even with backendTTL=0.
	req := makeRenewRequest(storage, internalData, time.Now().Add(-30*time.Minute), 3600*time.Second)

	resp, err := b.secretTokenRenew(ctx, req, nil)
	if err != nil {
		t.Fatalf("secretTokenRenew with deleted role: expected graceful fallback, got error: %v", err)
	}
	if resp == nil || resp.Secret == nil {
		t.Fatal("expected non-nil Secret on deleted-role fallback")
	}
	if resp.Secret.TTL <= 0 {
		t.Errorf("resp.Secret.TTL = %v; want > 0", resp.Secret.TTL)
	}
}

// TestSecretTokenRenew_DeletedRole_NoIncrement_UsesLeaseTTL verifies that when
// increment=0 and the role referenced by role_name is gone (deleted since issuance),
// renewal uses req.Secret.TTL (the lease's current TTL) as the backendTTL fallback —
// NOT the mount/system default.
//
// This is the N1 regression test: with the pre-fix code, backendTTL was left as 0
// for a deleted role, and CalculateTTL(increment=0, backendTTL=0, ...) would return
// the system DefaultLeaseTTL (24h in TestSystemView), not the lease's current TTL.
//
// Assertion: resp.Secret.TTL ≈ leaseTTL (45m), NOT sysview DefaultLeaseTTL (24h).
// The two values are distinct by design so the assertion is meaningful.
func TestSecretTokenRenew_DeletedRole_NoIncrement_UsesLeaseTTL(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	const (
		userid = "vault-myrole-noincrement007@pve"
		group  = "vault-vm-admins"
		// effectiveMaxTTL must be larger than leaseTTL so the renewal is not rejected.
		effectiveMaxTTL = 24 * time.Hour
		// leaseTTL is the current TTL of the lease — the expected fallback value.
		// This must differ from the sysview DefaultLeaseTTL (24h) so the test assertion
		// is meaningful. 45m is clearly distinct from 24h.
		leaseTTL = 45 * time.Minute
	)

	b, storage := setupBackendForRenew(t, userid, group, true, nil)
	// Do NOT write a role named "deleted-role" — it should be absent from storage.

	internalData := map[string]interface{}{
		"pve_userid":        userid,
		"group":             group,
		"effective_max_ttl": int64(effectiveMaxTTL),
		"role_name":         "deleted-role", // role does not exist in storage
		"expire":            time.Now().Add(effectiveMaxTTL).Unix(),
	}
	req := makeRenewRequest(storage, internalData, time.Now().Add(-30*time.Minute), 0 /* increment=0 */)
	// Override the Secret.TTL to a known value distinct from the sysview default.
	req.Secret.TTL = leaseTTL

	resp, err := b.secretTokenRenew(ctx, req, nil)
	if err != nil {
		t.Fatalf("secretTokenRenew with deleted role + increment=0: unexpected error: %v", err)
	}
	if resp == nil || resp.Secret == nil {
		t.Fatal("expected non-nil Secret on deleted-role no-increment fallback")
	}
	if resp.Secret.TTL <= 0 {
		t.Errorf("resp.Secret.TTL = %v; want > 0", resp.Secret.TTL)
	}

	// The sysview DefaultLeaseTTL is 24h (from TestSystemView). With the pre-fix
	// backendTTL=0 path, CalculateTTL would return 24h instead of leaseTTL.
	// Assert TTL is approximately leaseTTL (within 5s tolerance for test timing).
	diff := resp.Secret.TTL - leaseTTL
	if diff < 0 {
		diff = -diff
	}
	if diff > 5*time.Second {
		t.Errorf("resp.Secret.TTL = %v; want ~%v (lease-TTL fallback, not sysview default 24h); diff=%v",
			resp.Secret.TTL, leaseTTL, diff)
	}
}

// TestSecretTokenRenew_MultiGroup_WarnsNoFail verifies that when the post-update
// GetUser returns multiple groups (len > 1), renewal does NOT hard-fail — only
// a log warning is emitted. The containsGroup hard gate (the expected group is
// present) still passes.
func TestSecretTokenRenew_MultiGroup_WarnsNoFail(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	const (
		userid          = "vault-myrole-multigrp003@pve"
		group           = "vault-vm-admins"
		effectiveMaxTTL = 86400 * time.Second
	)

	getCallCount := 0
	b, storage := setupBackendForRenew(t, userid, group, true, func(mc *pveapi.MockClient) {
		mc.GetUserFn = func(_ context.Context, _ string) (pveapi.UserInfo, error) {
			getCallCount++
			if getCallCount == 1 {
				// pre-update: user enabled, in expected group
				return pveapi.UserInfo{Groups: []string{group}, Enable: true}, nil
			}
			// post-update: user now in TWO groups (unexpected cardinality)
			return pveapi.UserInfo{Groups: []string{group, "extra-grp"}, Enable: true}, nil
		}
		mc.UpdateUserFn = func(_ context.Context, _ pveapi.UpdateUserRequest) error {
			return nil
		}
	})

	internalData := standardRenewInternalData(effectiveMaxTTL)
	req := makeRenewRequest(storage, internalData, time.Now().Add(-30*time.Minute), 3600*time.Second)

	resp, err := b.secretTokenRenew(ctx, req, nil)
	// Must NOT fail — cardinality warning is soft.
	if err != nil {
		t.Fatalf("secretTokenRenew: unexpected error on multi-group: %v", err)
	}
	if resp == nil || resp.Secret == nil {
		t.Fatal("expected non-nil Secret on multi-group renewal")
	}
	if resp.Secret.TTL <= 0 {
		t.Errorf("resp.Secret.TTL = %v; want > 0", resp.Secret.TTL)
	}

	// containsGroup assertion still holds for the expected group.
	// (No hard assertion on the log line — we just verify non-fail behavior.)
}

// ── secretTokenRevoke tests ──────────────────────────────────────────────────

// TestSecretTokenRevoke_HappyPath verifies that revocation calls DeleteUser
// and returns (nil,nil).
func TestSecretTokenRevoke_HappyPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	const userid = "vault-myrole-revoke123@pve"

	deleteCalledWith := ""
	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		mc.DeleteUserFn = func(_ context.Context, uid string) error {
			deleteCalledWith = uid
			return nil
		}
	})
	if _, err := writeConfig(ctx, b, storage, validConfigData()); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}

	internalData := map[string]interface{}{
		"pve_userid":        userid,
		"group":             "vault-vm-admins",
		"effective_max_ttl": int64(86400 * time.Second),
	}
	req := makeRevokeRequest(storage, internalData)

	resp, err := b.secretTokenRevoke(ctx, req, nil)
	if err != nil {
		t.Fatalf("secretTokenRevoke: unexpected error: %v", err)
	}
	if resp != nil {
		t.Errorf("expected nil response on success; got: %v", resp)
	}

	// DeleteUser must have been called with the correct userid.
	if deleteCalledWith != userid {
		t.Errorf("DeleteUser called with %q; want %q", deleteCalledWith, userid)
	}
}

// TestSecretTokenRevoke_Idempotent_ErrUserNotFound verifies that revocation
// treats ErrUserNotFound (PVE HTTP 500 + body "no such user") as success,
// enabling idempotent revocation (lease already absent).
func TestSecretTokenRevoke_Idempotent_ErrUserNotFound(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	const userid = "vault-myrole-already-gone@pve"

	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		mc.DeleteUserFn = func(_ context.Context, _ string) error {
			// Simulate PVE HTTP 500 + body "no such user" (confirmed PVE 9.2.10 Probe 3).
			return fmt.Errorf("pveapi: DeleteUser: %w", pveapi.ErrUserNotFound)
		}
	})
	if _, err := writeConfig(ctx, b, storage, validConfigData()); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}

	internalData := map[string]interface{}{
		"pve_userid":        userid,
		"group":             "vault-vm-admins",
		"effective_max_ttl": int64(86400 * time.Second),
	}
	req := makeRevokeRequest(storage, internalData)

	resp, err := b.secretTokenRevoke(ctx, req, nil)
	if err != nil {
		t.Fatalf("secretTokenRevoke: expected nil for ErrUserNotFound (idempotent); got: %v", err)
	}
	if resp != nil {
		t.Errorf("expected nil response for idempotent revoke; got: %v", resp)
	}
}

// TestSecretTokenRevoke_TransientError verifies that a transient (non-ErrUserNotFound)
// error from DeleteUser causes revocation to return an error (so Vault retries),
// and the lease is NOT considered successfully revoked.
func TestSecretTokenRevoke_TransientError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	const userid = "vault-myrole-transient456@pve"
	transientErr := errors.New("network timeout during delete")

	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		mc.DeleteUserFn = func(_ context.Context, _ string) error {
			return transientErr
		}
	})
	if _, err := writeConfig(ctx, b, storage, validConfigData()); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}

	internalData := map[string]interface{}{
		"pve_userid":        userid,
		"group":             "vault-vm-admins",
		"effective_max_ttl": int64(86400 * time.Second),
	}
	req := makeRevokeRequest(storage, internalData)

	resp, err := b.secretTokenRevoke(ctx, req, nil)
	if err == nil {
		t.Fatal("expected error for transient DeleteUser failure; got nil")
		return
	}
	if resp != nil {
		t.Errorf("expected nil response on error; got: %v", resp)
	}
	// Error must wrap the transient error.
	if !errors.Is(err, transientErr) {
		t.Errorf("expected error to wrap transientErr; got: %v", err)
	}
}

// TestSecretTokenRenew_UnauthenticatedUpdateDiagnostic verifies DR-1 renewal
// diagnostics while preserving errors.Is for the unauthenticated sentinel.
func TestSecretTokenRenew_UnauthenticatedUpdateDiagnostic(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	const (
		userid          = "vault-myrole-unauth-renew@pve"
		group           = "vault-vm-admins"
		effectiveMaxTTL = 86400 * time.Second
	)

	getCallCount := 0
	b, storage := setupBackendForRenew(t, userid, group, true, func(mc *pveapi.MockClient) {
		mc.GetUserFn = func(_ context.Context, _ string) (pveapi.UserInfo, error) {
			getCallCount++
			return pveapi.UserInfo{Groups: []string{group}, Enable: true}, nil
		}
		mc.UpdateUserFn = func(_ context.Context, _ pveapi.UpdateUserRequest) error {
			return fmt.Errorf("pveapi: UpdateUser: %w", pveapi.ErrUnauthenticated)
		}
	})

	req := makeRenewRequest(storage, standardRenewInternalData(effectiveMaxTTL), time.Now().Add(-30*time.Minute), 3600*time.Second)
	resp, err := b.secretTokenRenew(ctx, req, nil)
	if err == nil {
		t.Fatal("expected unauthenticated renewal error, got nil")
		return
	}
	if resp != nil && resp.Secret != nil {
		t.Error("resp.Secret must be nil on renewal failure")
	}
	if !errors.Is(err, pveapi.ErrUnauthenticated) {
		t.Fatalf("expected errors.Is ErrUnauthenticated; got %v", err)
	}
	if !strings.Contains(err.Error(), "admin token unauthenticated") || !strings.Contains(err.Error(), "check config credentials") {
		t.Errorf("error missing admin-token diagnostic: %q", err.Error())
	}
	if getCallCount != 1 {
		t.Errorf("GetUser call count = %d; want 1 pre-update call", getCallCount)
	}
}

// TestSecretTokenRevoke_UnauthenticatedDiagnostic verifies DR-1 revocation
// diagnostics while preserving errors.Is for Vault retry/error handling.
func TestSecretTokenRevoke_UnauthenticatedDiagnostic(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	const userid = "vault-myrole-unauth-revoke@pve"

	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		mc.DeleteUserFn = func(_ context.Context, _ string) error {
			return fmt.Errorf("pveapi: DeleteUser: %w", pveapi.ErrUnauthenticated)
		}
	})
	if _, err := writeConfig(ctx, b, storage, validConfigData()); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}

	internalData := map[string]interface{}{
		"pve_userid":        userid,
		"group":             "vault-vm-admins",
		"effective_max_ttl": int64(86400 * time.Second),
	}
	req := makeRevokeRequest(storage, internalData)

	resp, err := b.secretTokenRevoke(ctx, req, nil)
	if err == nil {
		t.Fatal("expected unauthenticated revoke error, got nil")
		return
	}
	if resp != nil {
		t.Errorf("expected nil response on revoke error; got: %v", resp)
	}
	if !errors.Is(err, pveapi.ErrUnauthenticated) {
		t.Fatalf("expected errors.Is ErrUnauthenticated; got %v", err)
	}
	if !strings.Contains(err.Error(), "admin token unauthenticated") || !strings.Contains(err.Error(), "check config credentials") {
		t.Errorf("error missing admin-token diagnostic: %q", err.Error())
	}
}
