// Package proxmox — unit tests for password-mode credentials.
//
// Covers (docs/IMPLEMENTATION_PLAN.md P6):
//   - generatePassword: length, charset, PVE bounds, uniqueness.
//   - Role schema: mode validation, legacy (absent mode) roles, realm gating.
//   - Password issuance: exact response contract, CreateUser carries the
//     password, CreateToken is NEVER called, InternalData/WAL/storage hold no
//     password.
//   - Compensation: group read-back failure, comment/nonce mismatch (fatal in
//     password mode), transient DeleteUser retaining the WAL, collision retry
//     and exhaustion, and DeleteWAL failure on the success path.
//   - Lifecycle: the password secret type is registered and shares the
//     mode-independent renew/revoke callbacks, and renewal never returns a
//     password.
package proxmox

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	pveapi "github.com/hazmei/vault-plugin-secrets-proxmox/internal/pveapi"
)

// passwordRoleData returns a minimal valid password-mode role.
func passwordRoleData() map[string]interface{} {
	d := credRoleData()
	d["mode"] = modePassword
	return d
}

// issuedPassword extracts the password from a creds response, failing the test
// if the response does not carry one.
func issuedPassword(t *testing.T, resp *logical.Response) string {
	t.Helper()
	if resp == nil || resp.Secret == nil {
		t.Fatal("expected a response carrying a Secret")
	}
	pw, ok := resp.Data["password"].(string)
	if !ok || pw == "" {
		t.Fatalf("expected non-empty password in resp.Data, got %#v", resp.Data["password"])
	}
	return pw
}

// storageContains reports whether needle appears in any value stored under the
// given storage view, walking every key recursively. Used to prove that the
// generated password never lands in backend-controlled storage (roles, config,
// WAL entries). It deliberately does NOT cover Vault lease storage: Vault core
// persists the returned secret response in the encrypted lease entry, which is
// outside req.Storage and outside the backend's control.
func storageContains(ctx context.Context, t *testing.T, storage logical.Storage, prefix, needle string) bool {
	t.Helper()
	keys, err := storage.List(ctx, prefix)
	if err != nil {
		t.Fatalf("storage.List(%q): %v", prefix, err)
	}
	for _, k := range keys {
		full := prefix + k
		if strings.HasSuffix(k, "/") {
			if storageContains(ctx, t, storage, full, needle) {
				return true
			}
			continue
		}
		entry, err := storage.Get(ctx, full)
		if err != nil {
			t.Fatalf("storage.Get(%q): %v", full, err)
		}
		if entry != nil && strings.Contains(string(entry.Value), needle) {
			return true
		}
	}
	return false
}

// ── generatePassword ─────────────────────────────────────────────────────────

func TestGeneratePassword_ShapeAndUniqueness(t *testing.T) {
	t.Parallel()

	seen := make(map[string]bool, 100)
	for i := 0; i < 100; i++ {
		pw, err := generatePassword()
		if err != nil {
			t.Fatalf("generatePassword: %v", err)
		}
		if len(pw) != passwordLength {
			t.Fatalf("password length = %d, want %d", len(pw), passwordLength)
		}
		if len(pw) < pvePasswordMinLength || len(pw) > pvePasswordMaxLength {
			t.Fatalf("password length %d outside PVE-accepted %d..%d", len(pw), pvePasswordMinLength, pvePasswordMaxLength)
		}
		for _, r := range pw {
			if !strings.ContainsRune(passwordCharset, r) {
				t.Fatalf("password contains character %q outside the locked charset", r)
			}
		}
		if seen[pw] {
			t.Fatal("generatePassword returned a duplicate value across 100 draws")
		}
		seen[pw] = true
	}
}

// ── Role schema ──────────────────────────────────────────────────────────────

func TestRoleWrite_ModeValidation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	cases := []struct {
		name    string
		mode    string
		realm   string
		wantErr string
	}{
		{name: "password mode accepted on pve realm", mode: modePassword, realm: "pve"},
		{name: "token mode accepted", mode: modeToken, realm: "pve"},
		{name: "empty mode defaults to token", mode: "", realm: "pve"},
		{name: "unknown mode rejected", mode: "certificate", realm: "pve", wantErr: "invalid mode"},
		{name: "password mode rejected on pam realm", mode: modePassword, realm: "pam", wantErr: "requires realm"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			b, storage := setupBackendForCreds(t, "seed", credRoleData(), func(mc *pveapi.MockClient) {
				mc.GetPermissionsResult = pveapi.PermissionTree{
					"/access/groups":                 {"User.Modify": 1, "Sys.Audit": 1},
					"/access/groups/vault-vm-admins": {"User.Modify": 1},
					"/access/realm/pve":              {"Realm.AllocateUser": 1},
					"/access/realm/pam":              {"Realm.AllocateUser": 1},
				}
			})

			data := credRoleData()
			data["realm"] = tc.realm
			if tc.mode != "" {
				data["mode"] = tc.mode
			}

			resp, err := writeRole(ctx, b, storage, "modetest", data)
			if err != nil {
				t.Fatalf("writeRole: %v", err)
			}
			if tc.wantErr != "" {
				if resp == nil || !resp.IsError() {
					t.Fatalf("expected error response containing %q, got %#v", tc.wantErr, resp)
				}
				if !strings.Contains(resp.Error().Error(), tc.wantErr) {
					t.Fatalf("error %q does not contain %q", resp.Error(), tc.wantErr)
				}
				return
			}
			if resp != nil && resp.IsError() {
				t.Fatalf("unexpected error response: %s", resp.Error())
			}

			role, err := getRole(ctx, storage, "modetest")
			if err != nil {
				t.Fatalf("getRole: %v", err)
			}
			want := tc.mode
			if want == "" {
				want = modeToken
			}
			if role.Mode != want {
				t.Fatalf("stored mode = %q, want %q", role.Mode, want)
			}
		})
	}
}

// TestRoleWrite_PasswordModeWarnsAboutVerifiedBuild verifies that opting into
// password mode surfaces the narrower verification record at the point of
// opt-in: it is verified end to end only on passwordVerifiedBuild, while the
// project's declared target (9.2.10) has no password evidence.
func TestRoleWrite_PasswordModeWarnsAboutVerifiedBuild(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	b, storage := setupBackendForCreds(t, "seed", credRoleData(), nil)

	resp, err := writeRole(ctx, b, storage, "pwrole", passwordRoleData())
	if err != nil {
		t.Fatalf("writeRole: %v", err)
	}
	if resp == nil || len(resp.Warnings) == 0 {
		t.Fatal("password-mode role write must return a verification-scope warning")
	}
	joined := strings.Join(resp.Warnings, " ")
	if !strings.Contains(joined, passwordVerifiedBuild) {
		t.Errorf("warning must name the verified build %q; got %q", passwordVerifiedBuild, joined)
	}
	if !strings.Contains(joined, "9.2.10") {
		t.Errorf("warning must name the unverified declared target; got %q", joined)
	}

	// Token mode must stay warning-free.
	tokResp, err := writeRole(ctx, b, storage, "tokrole", credRoleData())
	if err != nil {
		t.Fatalf("writeRole token mode: %v", err)
	}
	if tokResp != nil && len(tokResp.Warnings) > 0 {
		t.Errorf("token-mode role write must not warn; got %v", tokResp.Warnings)
	}
}

// TestGetRole_LegacyRoleWithoutModeIsToken verifies backward compatibility:
// a role persisted before the mode field existed decodes with an empty mode and
// must normalize to token so its behavior is unchanged.
func TestGetRole_LegacyRoleWithoutModeIsToken(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	_, storage := setupBackendForCreds(t, "legacy", credRoleData(), nil)

	// Write a role document with NO mode key at all, as an old version would have.
	legacy := map[string]interface{}{
		"group":       "vault-vm-admins",
		"user_prefix": "vault",
		"realm":       "pve",
		"ttl":         3600,
		"max_ttl":     86400,
	}
	entry, err := logical.StorageEntryJSON("roles/legacy", legacy)
	if err != nil {
		t.Fatalf("StorageEntryJSON: %v", err)
	}
	if putErr := storage.Put(ctx, entry); putErr != nil {
		t.Fatalf("Put: %v", putErr)
	}

	role, err := getRole(ctx, storage, "legacy")
	if err != nil {
		t.Fatalf("getRole: %v", err)
	}
	if role.Mode != modeToken {
		t.Fatalf("legacy role mode = %q, want %q", role.Mode, modeToken)
	}
}

// ── Issuance ─────────────────────────────────────────────────────────────────

// TestCredsRead_PasswordMode_HappyPath asserts the full password contract:
// exactly user_id+password in the response, the password reaching CreateUser,
// no CreateToken call in any form, InternalData identical to token mode, and no
// password anywhere in backend-controlled storage or the WAL.
func TestCredsRead_PasswordMode_HappyPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	var mc *pveapi.MockClient
	b, storage := setupBackendForCreds(t, "pwrole", passwordRoleData(), func(m *pveapi.MockClient) {
		mc = m
	})

	resp, err := readCreds(ctx, b, storage, "pwrole")
	if err != nil {
		t.Fatalf("readCreds: %v", err)
	}
	if resp == nil || resp.IsError() {
		t.Fatalf("unexpected error response: %#v", resp)
	}
	pw := issuedPassword(t, resp)

	// Response contract: exactly user_id and password.
	if len(resp.Data) != 2 {
		t.Fatalf("resp.Data must contain exactly user_id and password, got %#v", resp.Data)
	}
	userid, _ := resp.Data["user_id"].(string)
	if userid == "" {
		t.Fatal("resp.Data missing user_id")
	}
	for _, forbidden := range []string{"token_id", "token_secret"} {
		if _, present := resp.Data[forbidden]; present {
			t.Errorf("password-mode response must not contain %q", forbidden)
		}
	}
	if resp.Secret.TTL <= 0 {
		t.Error("expected a positive lease TTL")
	}
	if resp.Secret.InternalData["pve_userid"] != userid {
		t.Errorf("InternalData pve_userid = %v, want %q", resp.Secret.InternalData["pve_userid"], userid)
	}

	// CreateToken must NEVER be called in password mode.
	if mc.HasCall("CreateToken") {
		t.Error("CreateToken must never be called in password mode")
	}

	// The password must have been sent on CreateUser, and match what was returned.
	createCalls := mc.CallsFor("CreateUser")
	if len(createCalls) != 1 {
		t.Fatalf("expected 1 CreateUser call, got %d", len(createCalls))
	}
	createReq, ok := createCalls[0].Args[0].(pveapi.CreateUserRequest)
	if !ok {
		t.Fatalf("unexpected CreateUser arg type %T", createCalls[0].Args[0])
	}
	if createReq.Password != pw {
		t.Error("CreateUser password does not match the password returned to the caller")
	}
	if createReq.Groups != "vault-vm-admins" {
		t.Errorf("CreateUser groups = %q, want the role group", createReq.Groups)
	}

	// The password must not appear in InternalData...
	for k, v := range resp.Secret.InternalData {
		if s, isStr := v.(string); isStr && strings.Contains(s, pw) {
			t.Errorf("InternalData[%q] contains the password", k)
		}
	}
	// ...nor anywhere in backend-controlled storage, including WAL entries.
	if storageContains(ctx, t, storage, "", pw) {
		t.Error("password found in backend-controlled storage")
	}
}

// TestCredsRead_PasswordMode_GroupReadBackFailure verifies that a failed group
// assertion deletes the already-live credential via the shared cleanupUser
// helper and returns no password.
func TestCredsRead_PasswordMode_GroupReadBackFailure(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	var mc *pveapi.MockClient
	b, storage := setupBackendForCreds(t, "pwrole", passwordRoleData(), func(m *pveapi.MockClient) {
		mc = m
		// Read-back returns a user with no group membership.
		m.GetUserFn = func(_ context.Context, _ string) (pveapi.UserInfo, error) {
			return pveapi.UserInfo{Groups: nil, Enable: true}, nil
		}
	})

	resp, err := readCreds(ctx, b, storage, "pwrole")
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatal("expected issuance to fail when the group read-back assertion fails")
	}
	if resp != nil && resp.Secret != nil {
		t.Error("no Secret may be returned when the group assertion fails")
	}
	if !mc.HasCall("DeleteUser") {
		t.Error("the live credential's user must be deleted after a group read-back failure")
	}
	remaining, err := countWALEntries(ctx, storage)
	if err != nil {
		t.Fatalf("countWALEntries: %v", err)
	}
	if remaining != 0 {
		t.Errorf("WAL entries = %d, want 0 after a successful compensating DeleteUser", remaining)
	}
}

// TestCredsRead_PasswordMode_CommentMismatchIsFatal verifies the P1-locked
// password comment policy: a nonce mismatch deletes the user and fails
// issuance, rather than warning and returning the credential as token mode does.
func TestCredsRead_PasswordMode_CommentMismatchIsFatal(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	var mc *pveapi.MockClient
	b, storage := setupBackendForCreds(t, "pwrole", passwordRoleData(), func(m *pveapi.MockClient) {
		mc = m
		m.GetUserFn = func(_ context.Context, _ string) (pveapi.UserInfo, error) {
			// Group is correct; the ownership marker was dropped.
			return pveapi.UserInfo{Groups: []string{"vault-vm-admins"}, Enable: true, Comment: "edited-by-hand"}, nil
		}
	})

	resp, err := readCreds(ctx, b, storage, "pwrole")
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatal("expected issuance to fail on a password-mode comment mismatch")
	}
	if resp != nil && resp.Secret != nil {
		t.Error("no Secret may be returned on a comment mismatch")
	}
	if !mc.HasCall("DeleteUser") {
		t.Error("the live credential's user must be deleted on a password-mode comment mismatch")
	}
}

// TestCredsRead_TokenMode_CommentMismatchIsNotFatal pins the contrasting token
// behavior: the soft warning path still issues the credential.
func TestCredsRead_TokenMode_CommentMismatchIsNotFatal(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	var mc *pveapi.MockClient
	b, storage := setupBackendForCreds(t, "tokrole", credRoleData(), func(m *pveapi.MockClient) {
		mc = m
		m.GetUserFn = func(_ context.Context, _ string) (pveapi.UserInfo, error) {
			return pveapi.UserInfo{Groups: []string{"vault-vm-admins"}, Enable: true, Comment: "edited-by-hand"}, nil
		}
	})

	resp, err := readCreds(ctx, b, storage, "tokrole")
	if err != nil {
		t.Fatalf("readCreds: %v", err)
	}
	if resp == nil || resp.IsError() || resp.Secret == nil {
		t.Fatalf("token mode must still issue on a comment mismatch, got %#v", resp)
	}
	if mc.HasCall("DeleteUser") {
		t.Error("token mode must not delete the user on a comment mismatch")
	}
}

// TestCredsRead_PasswordMode_TransientDeleteRetainsWAL verifies the WAL cleanup
// discipline on the password path: when the compensating DeleteUser fails
// transiently, the WAL entry is retained for walRollback.
func TestCredsRead_PasswordMode_TransientDeleteRetainsWAL(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	b, storage := setupBackendForCreds(t, "pwrole", passwordRoleData(), func(m *pveapi.MockClient) {
		m.GetUserFn = func(_ context.Context, _ string) (pveapi.UserInfo, error) {
			return pveapi.UserInfo{Groups: nil, Enable: true}, nil
		}
		m.DeleteUserError = errors.New("pve unreachable")
	})

	resp, err := readCreds(ctx, b, storage, "pwrole")
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatal("expected issuance to fail")
	}
	remaining, err := countWALEntries(ctx, storage)
	if err != nil {
		t.Fatalf("countWALEntries: %v", err)
	}
	if remaining != 1 {
		t.Errorf("WAL entries = %d, want 1 retained for walRollback after a transient DeleteUser failure", remaining)
	}
}

// TestCredsRead_PasswordMode_CollisionRetryAndExhaustion covers both the
// bounded retry loop and its exhaustion, asserting no token is ever minted.
func TestCredsRead_PasswordMode_CollisionRetryAndExhaustion(t *testing.T) {
	t.Parallel()

	t.Run("retry then succeed", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()

		var mc *pveapi.MockClient
		calls := 0
		b, storage := setupBackendForCreds(t, "pwrole", passwordRoleData(), func(m *pveapi.MockClient) {
			mc = m
			m.CreateUserFn = func(_ context.Context, req pveapi.CreateUserRequest) error {
				calls++
				if calls == 1 {
					return pveapi.ErrConflict
				}
				m.Users = map[string]pveapi.UserInfo{
					req.UserID: {Groups: []string{req.Groups}, Enable: true, Comment: req.Comment},
				}
				return nil
			}
		})

		resp, err := readCreds(ctx, b, storage, "pwrole")
		if err != nil {
			t.Fatalf("readCreds: %v", err)
		}
		issuedPassword(t, resp)
		if calls != 2 {
			t.Errorf("CreateUser attempts = %d, want 2", calls)
		}
		if mc.HasCall("CreateToken") {
			t.Error("CreateToken must never be called in password mode, including on retries")
		}
	})

	t.Run("exhaustion", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()

		var mc *pveapi.MockClient
		b, storage := setupBackendForCreds(t, "pwrole", passwordRoleData(), func(m *pveapi.MockClient) {
			mc = m
			m.CreateUserFn = func(_ context.Context, _ pveapi.CreateUserRequest) error {
				return pveapi.ErrConflict
			}
		})

		resp, err := readCreds(ctx, b, storage, "pwrole")
		if err == nil && (resp == nil || !resp.IsError()) {
			t.Fatal("expected collision exhaustion to fail issuance")
		}
		if err != nil && strings.Contains(err.Error(), passwordCharset[:8]) {
			t.Error("exhaustion error must not contain generated material")
		}
		if mc.HasCall("CreateToken") {
			t.Error("CreateToken must never be called in password mode")
		}
		remaining, walErr := countWALEntries(ctx, storage)
		if walErr != nil {
			t.Fatalf("countWALEntries: %v", walErr)
		}
		if remaining != 0 {
			t.Errorf("WAL entries = %d, want 0 after all attempts collided and were cleaned", remaining)
		}
	})
}

// TestCredsRead_PasswordMode_DeleteWALFailOnSuccessPath verifies that a
// DeleteWAL failure after the password is live withholds the credential and
// best-effort deletes the user. CreateUser is pinned to succeed on the first
// attempt so a collision retry cannot mask the branch under test.
func TestCredsRead_PasswordMode_DeleteWALFailOnSuccessPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	mc := &pveapi.MockClient{}
	mc.GetPermissionsResult = pveapi.PermissionTree{
		"/access/groups":                 {"User.Modify": 1, "Sys.Audit": 1},
		"/access/groups/vault-vm-admins": {"User.Modify": 1},
		"/access/realm/pve":              {"Realm.AllocateUser": 1},
	}
	mc.Groups = map[string]bool{"vault-vm-admins": true}

	innerConfig := logical.TestBackendConfig()
	innerConfig.StorageView = &logical.InmemStorage{}
	b, err := newBackend(ctx, innerConfig)
	if err != nil {
		t.Fatalf("newBackend: %v", err)
	}
	b.newClient = func(_ *proxmoxConfig) (pveapi.Client, error) { return mc, nil }

	innerStorage := innerConfig.StorageView
	if _, err := writeConfig(ctx, b, innerStorage, validConfigData()); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}
	if _, err := writeRole(ctx, b, innerStorage, "pwrole", passwordRoleData()); err != nil {
		t.Fatalf("writeRole: %v", err)
	}

	failStorage := &failingDeleteStorage{Storage: innerStorage, failPrefix: framework.WALPrefix}
	resp, reqErr := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/pwrole",
		Storage:   failStorage,
	})

	if reqErr == nil && (resp == nil || !resp.IsError()) {
		t.Fatal("expected issuance to fail when DeleteWAL fails on the success path")
	}
	if resp != nil && resp.Secret != nil {
		t.Error("no Secret may be returned when DeleteWAL fails")
	}
	if resp != nil {
		if _, present := resp.Data["password"]; present {
			t.Error("the password must not be returned when DeleteWAL fails")
		}
	}
	if !mc.HasCall("DeleteUser") {
		t.Error("best-effort DeleteUser must run after a DeleteWAL failure on the success path")
	}
}

// ── Lifecycle ────────────────────────────────────────────────────────────────

// TestSecretPassword_Registered verifies the password secret type is registered
// with non-nil renew/revoke callbacks (a nil Renew would silently make every
// password lease non-renewable).
func TestSecretPassword_Registered(t *testing.T) {
	t.Parallel()

	b, _ := newTestBackend(t, nil)
	s := b.Secret(secretTypePassword)
	if s == nil {
		t.Fatalf("secret type %q is not registered", secretTypePassword)
		return
	}
	if s.Renew == nil {
		t.Error("password secret Renew must be non-nil or leases are non-renewable")
	}
	if s.Revoke == nil {
		t.Error("password secret Revoke must be non-nil")
	}
	if b.Secret(secretTypeToken) == nil {
		t.Error("the token secret type must remain registered")
	}
}

// TestSecretPassword_RenewExtendsWithoutReturningPassword verifies that renewal
// of a password lease extends the PVE expiry, preserves group membership, and
// never rotates or returns a password.
func TestSecretPassword_RenewExtendsWithoutReturningPassword(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	userid := "vault-myrole-abc12345@pve"
	var mc *pveapi.MockClient
	b, storage := setupBackendForRenew(t, userid, "vault-vm-admins", true, func(m *pveapi.MockClient) {
		mc = m
	})

	req := makeRenewRequest(storage, standardRenewInternalData(24*time.Hour), time.Now(), 0)
	resp, err := b.Secret(secretTypePassword).Renew(ctx, req, nil)
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	if resp == nil || resp.Secret == nil {
		t.Fatal("expected a renewed Secret")
	}
	if resp.Secret.TTL <= 0 {
		t.Error("expected a positive TTL after renewal")
	}
	if _, present := resp.Data["password"]; present {
		t.Error("renewal must never return a password")
	}

	updates := mc.CallsFor("UpdateUser")
	if len(updates) != 1 {
		t.Fatalf("expected 1 UpdateUser call, got %d", len(updates))
	}
	upd, ok := updates[0].Args[0].(pveapi.UpdateUserRequest)
	if !ok {
		t.Fatalf("unexpected UpdateUser arg type %T", updates[0].Args[0])
	}
	if !upd.Append || upd.Groups != "vault-vm-admins" || !upd.Enable || upd.Expire <= 0 {
		t.Errorf("renewal PUT must re-send expire+groups+enable+append=1, got %#v", upd)
	}
}

// TestSecretPassword_RevokeDeletesUser verifies revocation deletes the PVE user
// and is idempotent, using the shared mode-independent callback.
func TestSecretPassword_RevokeDeletesUser(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	userid := "vault-myrole-abc12345@pve"
	var mc *pveapi.MockClient
	b, storage := setupBackendForRenew(t, userid, "vault-vm-admins", true, func(m *pveapi.MockClient) {
		mc = m
	})

	req := makeRevokeRequest(storage, standardRenewInternalData(24*time.Hour))
	if _, err := b.Secret(secretTypePassword).Revoke(ctx, req, nil); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	deleted := mc.DeleteUserCalls()
	if len(deleted) != 1 || deleted[0] != userid {
		t.Fatalf("DeleteUser calls = %v, want [%s]", deleted, userid)
	}

	// Idempotent: a second revoke against an absent user must still succeed.
	mc.DeleteUserError = pveapi.ErrUserNotFound
	if _, err := b.Secret(secretTypePassword).Revoke(ctx, makeRevokeRequest(storage, standardRenewInternalData(24*time.Hour)), nil); err != nil {
		t.Fatalf("idempotent revoke: %v", err)
	}
}
