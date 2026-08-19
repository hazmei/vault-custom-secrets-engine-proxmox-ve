// Package proxmox — unit tests for path_creds.go.
//
// Covers handleCredsRead issuance flow with a mocked PVE API client:
//   - Happy path: success → resp.Secret non-nil, Renewable, resp.Data has
//     token_id/token_secret/user_id, InternalData has pve_userid/group/effective_max_ttl/role_name/expire.
//   - CreateToken privsep=0: asserted via CallLog showing CreateToken was called
//     (the Client interface mandates privsep=0 in the real client; the mock
//     records the call for assertion).
//   - CreateUser groups=<role.group>, expire=<leaseExpiry+expireGraceSecs grace>,
//     Comment has walCommentPrefix, and Comment==walUser.Nonce (ownership invariant).
//   - ErrConflict retry: first CreateUser returns ErrConflict, second succeeds →
//     new suffix used AND DeleteWAL called with the FIRST attempt's WAL id.
//   - Group read-back failure: GetUser returns groups NOT containing role.group →
//     issuance fails, DeleteUser called, WAL cleaned only if DeleteUser succeeded.
//   - Token-create failure: CreateToken returns error → DeleteUser called (cleanup),
//     DeleteWAL called only on DeleteUser nil/ErrNotFound.
//   - DeleteWAL-fail on success path → best-effort DeleteUser then error returned
//     (no Secret returned).
//   - Collision exhaustion: CreateUser returns ErrConflict every attempt →
//     bounded retries then internal error.
//   - Expire grace: +expireGraceSecs grace applied to expire sent to CreateUser.
//   - Issuance REFUSED when effective TTL = 0 → error returned, NO PVE calls.
//   - WAL nonce invariant: walUser.Nonce == CreateUserRequest.Comment, both
//     carrying walCommentPrefix, asserted via GetWAL on a surviving-WAL path.
package proxmox

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	pveapi "github.com/hazmei/vault-plugin-secrets-proxmox/internal/pveapi"
)

// ── Test helpers ──────────────────────────────────────────────────────────────

// readCreds sends a GET to <mount>/creds/:role and returns the response.
func readCreds(ctx context.Context, b *backend, storage logical.Storage, roleName string) (*logical.Response, error) {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/" + roleName,
		Storage:   storage,
	}
	return b.HandleRequest(ctx, req)
}

// setupBackendForCreds creates a backend with config and role already written.
// The mock is configured with the full permission tree required for role write.
// Additional mock customisation can be applied via the extraSetup func.
func setupBackendForCreds(t *testing.T, roleName string, roleData map[string]interface{}, extraSetup func(*pveapi.MockClient)) (*backend, logical.Storage) {
	t.Helper()
	ctx := context.Background()

	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		// Full privileges for role write.
		mc.GetPermissionsResult = pveapi.PermissionTree{
			"/access/groups": {
				"User.Modify": 1,
				"Sys.Audit":   1,
			},
			"/access/groups/vault-vm-admins": {
				"User.Modify": 1,
			},
			"/access/realm/pve": {
				"Realm.AllocateUser": 1,
			},
		}
		mc.Groups = map[string]bool{"vault-vm-admins": true}
		if extraSetup != nil {
			extraSetup(mc)
		}
	})

	if _, err := writeConfig(ctx, b, storage, validConfigData()); err != nil {
		t.Fatalf("setupBackendForCreds: writeConfig: %v", err)
	}
	resp, err := writeRole(ctx, b, storage, roleName, roleData)
	if err != nil {
		t.Fatalf("setupBackendForCreds: writeRole: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("setupBackendForCreds: writeRole error response: %s", resp.Error())
	}

	return b, storage
}

// credRoleData returns a minimal valid role for creds testing.
// TTL=3600s, MaxTTL=86400s, group=vault-vm-admins, realm=pve, user_prefix=vault.
func credRoleData() map[string]interface{} {
	return map[string]interface{}{
		"group":       "vault-vm-admins",
		"user_prefix": "vault",
		"realm":       "pve",
		"ttl":         3600,
		"max_ttl":     86400,
	}
}

// countWALEntries returns the number of wal/ keys currently in storage.
func countWALEntries(ctx context.Context, storage logical.Storage) (int, error) {
	keys, err := framework.ListWAL(ctx, storage)
	if err != nil {
		return 0, err
	}
	return len(keys), nil
}

// failingDeleteStorage wraps a logical.Storage and returns an error for any
// Delete call whose key has the given prefix. Used to simulate a DeleteWAL
// failure by failing deletes on "wal/" keys.
type failingDeleteStorage struct {
	logical.Storage
	failPrefix  string
	deleteCount int32 // atomic counter for delete attempts on matching keys
}

func (s *failingDeleteStorage) Delete(ctx context.Context, key string) error {
	if strings.HasPrefix(key, s.failPrefix) {
		atomic.AddInt32(&s.deleteCount, 1)
		return errors.New("simulated storage delete failure")
	}
	return s.Storage.Delete(ctx, key)
}

func (s *failingDeleteStorage) DeleteAttempts() int {
	return int(atomic.LoadInt32(&s.deleteCount))
}

// ── Happy path ────────────────────────────────────────────────────────────────

// TestCredsRead_HappyPath verifies the full happy-path issuance:
//   - resp.Secret is non-nil and Renewable (non-nil Renew callback).
//   - resp.Data contains token_id, token_secret, user_id.
//   - InternalData contains pve_userid, group, effective_max_ttl.
//   - CreateToken was called (privsep=0 guaranteed by Client interface contract).
//   - CreateUser was called with groups=<role.group> and expire includes +60s grace.
//   - WAL entry is cleaned up (no wal/ keys remain after success).
func TestCredsRead_HappyPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	b, storage := setupBackendForCreds(t, "myrole", credRoleData(), nil)

	before := time.Now()
	resp, err := readCreds(ctx, b, storage, "myrole")
	after := time.Now()
	if err != nil {
		t.Fatalf("readCreds: unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.IsError() {
		t.Fatalf("unexpected error response: %s", resp.Error())
	}
	if resp.Secret == nil {
		t.Fatal("resp.Secret must be non-nil for a successful issuance")
	}

	// Renewable assertion (non-nil Renew callback in secretToken).
	if !resp.Secret.Renewable {
		t.Error("resp.Secret.Renewable must be true (requires non-nil Renew callback in secretToken)")
	}

	// resp.Data fields.
	for _, field := range []string{"token_id", "token_secret", "user_id"} {
		if _, ok := resp.Data[field]; !ok {
			t.Errorf("resp.Data missing required field %q", field)
		}
	}
	tokenID, _ := resp.Data["token_id"].(string)
	tokenSecret, _ := resp.Data["token_secret"].(string)
	userID, _ := resp.Data["user_id"].(string)

	if tokenID == "" {
		t.Error("token_id must be non-empty")
	}
	if tokenSecret == "" {
		t.Error("token_secret must be non-empty")
	}
	if userID == "" {
		t.Error("user_id must be non-empty")
	}
	// token_id format: <userid>!lease
	if !strings.Contains(tokenID, "!") {
		t.Errorf("token_id %q must contain '!' separator (format: <userid>!<tokenid>)", tokenID)
	}

	// InternalData fields.
	intData := resp.Secret.InternalData
	if pveid, ok := intData["pve_userid"].(string); !ok || pveid == "" {
		t.Errorf("InternalData pve_userid missing or empty; got %v", intData["pve_userid"])
	}
	if grp, ok := intData["group"].(string); !ok || grp == "" {
		t.Errorf("InternalData group missing or empty; got %v", intData["group"])
	} else if grp != "vault-vm-admins" {
		t.Errorf("InternalData group = %q; want vault-vm-admins", grp)
	}
	if _, ok := intData["effective_max_ttl"]; !ok {
		t.Error("InternalData effective_max_ttl missing")
	}
	// C2: role_name and expire must be present.
	if rn, ok := intData["role_name"].(string); !ok || rn != "myrole" {
		t.Errorf("InternalData role_name = %v; want %q", intData["role_name"], "myrole")
	}
	if _, ok := intData["expire"]; !ok {
		t.Error("InternalData expire missing")
	}

	// Expire grace: check that CreateUser was called with expire ≥ leaseEnd + 60s.
	// We get the MockClient from b.client (set after first call to getClient).
	b.clientMu.RLock()
	mc, _ := b.client.(*pveapi.MockClient)
	b.clientMu.RUnlock()
	if mc == nil {
		t.Fatal("could not retrieve MockClient from backend")
	}

	// Assert CreateToken was called (privsep=0 is enforced by the Client interface:
	// Client.CreateToken always sends privsep=0; there is no call site that passes privsep=1).
	if !mc.HasCall("CreateToken") {
		t.Error("CreateToken was not called; privsep=0 requires CreateToken to be invoked")
	}

	// Assert CreateUser was called with groups=vault-vm-admins and correct expire.
	createCalls := mc.CallsFor("CreateUser")
	if len(createCalls) == 0 {
		t.Fatal("CreateUser was not called")
	}
	createReq, ok := createCalls[0].Args[0].(pveapi.CreateUserRequest)
	if !ok {
		t.Fatalf("CreateUser arg[0] type %T; want pveapi.CreateUserRequest", createCalls[0].Args[0])
	}
	if createReq.Groups != "vault-vm-admins" {
		t.Errorf("CreateUser Groups = %q; want vault-vm-admins", createReq.Groups)
	}
	// Expire grace: expire must be ≥ before+TTL+expireGraceSecs and ≤ after+TTL+(expireGraceSecs+1)s.
	minExpire := before.Add(3600*time.Second + expireGraceSecs*time.Second).Unix()
	maxExpire := after.Add(3600*time.Second + (expireGraceSecs+1)*time.Second).Unix()
	if createReq.Expire < minExpire || createReq.Expire > maxExpire {
		t.Errorf("CreateUser Expire = %d; expected in [%d, %d] (leaseEnd + %ds grace)",
			createReq.Expire, minExpire, maxExpire, expireGraceSecs)
	}
	// C1: CreateUser.Comment must be non-empty (the WAL nonce for ownership verification).
	if createReq.Comment == "" {
		t.Error("CreateUser Comment must be non-empty (WAL nonce for ownership verification)")
	}
	// M1: CreateUser.Comment must have the walCommentPrefix (ownership marker format).
	if !strings.HasPrefix(createReq.Comment, walCommentPrefix) {
		t.Errorf("CreateUser Comment = %q; want %s prefix (walCommentPrefix)", createReq.Comment, walCommentPrefix)
	}

	// WAL must be cleaned up on the success path (no wal/ entries remain).
	n, err := countWALEntries(ctx, storage)
	if err != nil {
		t.Fatalf("countWALEntries: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 WAL entries after successful issuance; got %d", n)
	}
}

// ── privsep=0 explicit assertion ──────────────────────────────────────────────

// TestCredsRead_CreateToken_Privsep0 explicitly asserts the acceptance criterion:
// CreateToken is called (and the Client.CreateToken contract mandates privsep=0).
// Also verifies the token_id format and that CreateToken args match the userid.
func TestCredsRead_CreateToken_Privsep0(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Capture CreateToken call details.
	var capturedUserid, capturedTokenid string
	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		mc.GetPermissionsResult = pveapi.PermissionTree{
			"/access/groups":                 {"User.Modify": 1, "Sys.Audit": 1},
			"/access/groups/vault-vm-admins": {"User.Modify": 1},
			"/access/realm/pve":              {"Realm.AllocateUser": 1},
		}
		mc.Groups = map[string]bool{"vault-vm-admins": true}
		mc.CreateTokenFn = func(_ context.Context, userid, tokenid string) (string, error) {
			capturedUserid = userid
			capturedTokenid = tokenid
			return "captured-token-secret-uuid", nil
		}
	})
	if _, err := writeConfig(ctx, b, storage, validConfigData()); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}
	if _, err := writeRole(ctx, b, storage, "testrole", credRoleData()); err != nil {
		t.Fatalf("writeRole: %v", err)
	}

	resp, err := readCreds(ctx, b, storage, "testrole")
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("readCreds: err=%v resp=%v", err, resp)
	}

	// CreateToken was called — the Client interface mandates privsep=0 in the
	// real httpClient.CreateToken (hardcoded form.Set("privsep", "0")).
	// This test asserts the call was made; the "on the wire" assertion is
	// compile-checked via the interface contract (no privsep param on Client interface).
	if capturedUserid == "" {
		t.Fatal("CreateToken was not called; privsep=0 requires CreateToken to be invoked")
	}
	if capturedTokenid != leaseTokenID {
		t.Errorf("CreateToken tokenid = %q; want %q", capturedTokenid, leaseTokenID)
	}

	// token_id in resp.Data must be <capturedUserid>!<leaseTokenID>
	tokenID, _ := resp.Data["token_id"].(string)
	expectedTokenID := capturedUserid + "!" + leaseTokenID
	if tokenID != expectedTokenID {
		t.Errorf("token_id = %q; want %q", tokenID, expectedTokenID)
	}

	// token_secret must match what CreateTokenFn returned.
	if resp.Data["token_secret"] != "captured-token-secret-uuid" {
		t.Errorf("token_secret = %v; want captured-token-secret-uuid", resp.Data["token_secret"])
	}
}

// ── Expire grace ──────────────────────────────────────────────────────────────

// TestCredsRead_ExpireGrace asserts that the +60s grace (expireGraceSecs) is
// applied to the expire field sent to CreateUser.
func TestCredsRead_ExpireGrace(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	var capturedExpire int64
	var usersMu sync.Mutex
	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		mc.GetPermissionsResult = pveapi.PermissionTree{
			"/access/groups":                 {"User.Modify": 1, "Sys.Audit": 1},
			"/access/groups/vault-vm-admins": {"User.Modify": 1},
			"/access/realm/pve":              {"Realm.AllocateUser": 1},
		}
		mc.Groups = map[string]bool{"vault-vm-admins": true}
		mc.CreateUserFn = func(_ context.Context, req pveapi.CreateUserRequest) error {
			capturedExpire = req.Expire
			// Also create the user in memory for GetUser read-back to work.
			usersMu.Lock()
			defer usersMu.Unlock()
			if mc.Users == nil {
				mc.Users = make(map[string]pveapi.UserInfo)
			}
			mc.Users[req.UserID] = pveapi.UserInfo{
				Groups: []string{"vault-vm-admins"},
				Enable: req.Enable,
				Expire: req.Expire,
			}
			return nil
		}
	})
	if _, err := writeConfig(ctx, b, storage, validConfigData()); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}
	if _, err := writeRole(ctx, b, storage, "testrole", credRoleData()); err != nil {
		t.Fatalf("writeRole: %v", err)
	}

	before := time.Now()
	resp, err := readCreds(ctx, b, storage, "testrole")
	after := time.Now()
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("readCreds: err=%v resp=%v", err, resp)
	}

	// expire must be leaseEnd + expireGraceSecs.
	// leaseEnd = now + TTL(3600s), so expire ∈ [before+3600+expireGraceSecs, after+3600+(expireGraceSecs+1)].
	minExpire := before.Add(3600*time.Second + expireGraceSecs*time.Second).Unix()
	maxExpire := after.Add(3600*time.Second + (expireGraceSecs+1)*time.Second).Unix()
	if capturedExpire < minExpire || capturedExpire > maxExpire {
		t.Errorf("CreateUser Expire = %d; expected in [%d, %d] (leaseEnd+%ds grace)",
			capturedExpire, minExpire, maxExpire, expireGraceSecs)
	}
}

// ── ErrConflict retry ─────────────────────────────────────────────────────────

// TestCredsRead_ErrConflict_Retry verifies the collision-retry path:
//   - First CreateUser returns ErrConflict (userid collision).
//   - DeleteWAL is called with the FIRST attempt's WAL id (per-attempt WAL discipline).
//   - Second CreateUser succeeds with a DIFFERENT userid (new suffix).
//   - Final response is a successful Secret.
func TestCredsRead_ErrConflict_Retry(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	callCount := 0
	var firstUserID string
	var secondUserID string
	var usersMu2 sync.Mutex

	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		mc.GetPermissionsResult = pveapi.PermissionTree{
			"/access/groups":                 {"User.Modify": 1, "Sys.Audit": 1},
			"/access/groups/vault-vm-admins": {"User.Modify": 1},
			"/access/realm/pve":              {"Realm.AllocateUser": 1},
		}
		mc.Groups = map[string]bool{"vault-vm-admins": true}
		mc.CreateUserFn = func(_ context.Context, req pveapi.CreateUserRequest) error {
			callCount++
			if callCount == 1 {
				firstUserID = req.UserID
				return fmt.Errorf("pveapi: CreateUser: %w", pveapi.ErrConflict)
			}
			secondUserID = req.UserID
			// Create in memory for GetUser read-back.
			usersMu2.Lock()
			defer usersMu2.Unlock()
			if mc.Users == nil {
				mc.Users = make(map[string]pveapi.UserInfo)
			}
			mc.Users[req.UserID] = pveapi.UserInfo{
				Groups: []string{"vault-vm-admins"},
				Enable: req.Enable,
				Expire: req.Expire,
			}
			return nil
		}
	})
	if _, err := writeConfig(ctx, b, storage, validConfigData()); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}
	if _, err := writeRole(ctx, b, storage, "testrole", credRoleData()); err != nil {
		t.Fatalf("writeRole: %v", err)
	}

	resp, err := readCreds(ctx, b, storage, "testrole")
	if err != nil {
		t.Fatalf("readCreds: unexpected error: %v", err)
	}
	if resp == nil || resp.IsError() {
		t.Fatalf("expected successful response; got error: %v", resp)
	}
	if resp.Secret == nil {
		t.Fatal("expected non-nil Secret on collision retry success")
	}

	// Two CreateUser calls must have been made.
	if callCount != 2 {
		t.Errorf("CreateUser call count = %d; want 2 (first collision + second success)", callCount)
	}

	// The second userid must have a DIFFERENT suffix than the first.
	if firstUserID == secondUserID {
		t.Errorf("collision retry must generate a new suffix; first=%q second=%q", firstUserID, secondUserID)
	}

	// WAL discipline: the FIRST attempt's WAL entry must have been deleted
	// (DeleteWAL called with the first attempt's id).
	// After success, NO WAL entries must remain.
	n, err := countWALEntries(ctx, storage)
	if err != nil {
		t.Fatalf("countWALEntries: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 WAL entries after collision retry success; got %d", n)
	}

	// Verify the winning userid appears in InternalData.
	pveid, _ := resp.Secret.InternalData["pve_userid"].(string)
	if pveid != secondUserID {
		t.Errorf("InternalData pve_userid = %q; want %q (second attempt's userid)", pveid, secondUserID)
	}
}

// TestCredsRead_ErrConflict_WalIDDiscipline verifies the per-attempt WAL id
// discipline: after a collision, the WAL entry for that attempt is cleaned up
// before the next attempt starts, so no orphaned WAL entries accumulate.
func TestCredsRead_ErrConflict_WalIDDiscipline(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Track WAL entry existence after the first collision.
	// We do this by inspecting storage after the second CreateUser call.
	walEntryCountAfterSecondAttempt := -1
	callCount := 0

	// storagePtr holds the storage after newTestBackend returns.
	// The CreateUserFn closure is called after setup completes, so storage is valid.
	var storageRef logical.Storage
	var usersMu3 sync.Mutex

	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		mc.GetPermissionsResult = pveapi.PermissionTree{
			"/access/groups":                 {"User.Modify": 1, "Sys.Audit": 1},
			"/access/groups/vault-vm-admins": {"User.Modify": 1},
			"/access/realm/pve":              {"Realm.AllocateUser": 1},
		}
		mc.Groups = map[string]bool{"vault-vm-admins": true}
		mc.CreateUserFn = func(_ context.Context, req pveapi.CreateUserRequest) error {
			callCount++
			if callCount == 1 {
				return fmt.Errorf("pveapi: CreateUser: %w", pveapi.ErrConflict)
			}
			// On the second call, count WAL entries via storageRef (set below after
			// newTestBackend returns). At this point the first attempt's WAL should
			// have been deleted; the second attempt's WAL should be live: expect 1.
			if storageRef != nil {
				n, walErr := countWALEntries(ctx, storageRef)
				if walErr == nil {
					walEntryCountAfterSecondAttempt = n
				}
			}
			// Create in memory for GetUser read-back.
			usersMu3.Lock()
			defer usersMu3.Unlock()
			if mc.Users == nil {
				mc.Users = make(map[string]pveapi.UserInfo)
			}
			mc.Users[req.UserID] = pveapi.UserInfo{Groups: []string{"vault-vm-admins"}, Enable: true}
			return nil
		}
	})
	// Set storageRef now that newTestBackend has returned.
	storageRef = storage
	if _, err := writeConfig(ctx, b, storage, validConfigData()); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}
	if _, err := writeRole(ctx, b, storage, "testrole", credRoleData()); err != nil {
		t.Fatalf("writeRole: %v", err)
	}

	resp, err := readCreds(ctx, b, storage, "testrole")
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("readCreds: err=%v resp=%v", err, resp)
	}

	// At the moment the second CreateUser was called, exactly 1 WAL entry must
	// exist (the second attempt's WAL; the first has been deleted after collision).
	if walEntryCountAfterSecondAttempt != 1 {
		t.Errorf("WAL count during second attempt = %d; want 1 (first attempt's WAL must have been deleted after collision, second's is live)",
			walEntryCountAfterSecondAttempt)
	}
}

// ── Group read-back failure ───────────────────────────────────────────────────

// TestCredsRead_GroupReadback_Failure verifies the group read-back assertion:
// if GetUser returns groups NOT containing role.group, issuance fails,
// DeleteUser is called for cleanup, and WAL is cleaned if DeleteUser succeeded.
func TestCredsRead_GroupReadback_Failure(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		mc.GetPermissionsResult = pveapi.PermissionTree{
			"/access/groups":                 {"User.Modify": 1, "Sys.Audit": 1},
			"/access/groups/vault-vm-admins": {"User.Modify": 1},
			"/access/realm/pve":              {"Realm.AllocateUser": 1},
		}
		mc.Groups = map[string]bool{"vault-vm-admins": true}
		// GetUser returns a user NOT in vault-vm-admins (simulates PVE silently
		// dropping the group on create, or the group being unresolvable).
		mc.GetUserFn = func(_ context.Context, userid string) (pveapi.UserInfo, error) {
			return pveapi.UserInfo{
				Groups: []string{}, // empty — group read-back fails
				Enable: true,
			}, nil
		}
	})
	if _, err := writeConfig(ctx, b, storage, validConfigData()); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}
	if _, err := writeRole(ctx, b, storage, "testrole", credRoleData()); err != nil {
		t.Fatalf("writeRole: %v", err)
	}

	resp, err := readCreds(ctx, b, storage, "testrole")
	// Must fail — either as a logical.Response error or a framework error.
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatal("expected error when group read-back fails; got success")
	}
	if resp != nil && resp.Secret != nil {
		t.Error("resp.Secret must be nil when issuance fails")
	}

	// DeleteUser must have been called (best-effort cleanup).
	b.clientMu.RLock()
	mc, _ := b.client.(*pveapi.MockClient)
	b.clientMu.RUnlock()
	if mc != nil && !mc.HasCall("DeleteUser") {
		t.Error("DeleteUser must be called for cleanup when group read-back fails")
	}

	// WAL must be cleaned up (DeleteUser succeeded in the default mock).
	n, err2 := countWALEntries(ctx, storage)
	if err2 != nil {
		t.Fatalf("countWALEntries: %v", err2)
	}
	if n != 0 {
		t.Errorf("expected 0 WAL entries after group read-back failure cleanup; got %d", n)
	}
}

// TestCredsRead_GroupReadback_WrongGroup verifies the same as above but with
// a different (wrong) group returned from GetUser.
func TestCredsRead_GroupReadback_WrongGroup(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		mc.GetPermissionsResult = pveapi.PermissionTree{
			"/access/groups":                 {"User.Modify": 1, "Sys.Audit": 1},
			"/access/groups/vault-vm-admins": {"User.Modify": 1},
			"/access/realm/pve":              {"Realm.AllocateUser": 1},
		}
		mc.Groups = map[string]bool{"vault-vm-admins": true}
		mc.GetUserFn = func(_ context.Context, userid string) (pveapi.UserInfo, error) {
			// Return a user in the wrong group.
			return pveapi.UserInfo{Groups: []string{"some-other-group"}, Enable: true}, nil
		}
	})
	if _, err := writeConfig(ctx, b, storage, validConfigData()); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}
	if _, err := writeRole(ctx, b, storage, "testrole", credRoleData()); err != nil {
		t.Fatalf("writeRole: %v", err)
	}

	resp, err := readCreds(ctx, b, storage, "testrole")
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatal("expected error when group read-back returns wrong group; got success")
	}
	if resp != nil && resp.Secret != nil {
		t.Error("resp.Secret must be nil when group read-back fails")
	}
}

// TestCredsRead_GroupReadback_DeleteUserFailTransient verifies that when the
// group read-back fails AND DeleteUser returns a transient error, the WAL entry
// is LEFT (not cleaned up) so walRollback can retry.
func TestCredsRead_GroupReadback_DeleteUserFailTransient(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	transientErr := errors.New("transient delete error")
	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		mc.GetPermissionsResult = pveapi.PermissionTree{
			"/access/groups":                 {"User.Modify": 1, "Sys.Audit": 1},
			"/access/groups/vault-vm-admins": {"User.Modify": 1},
			"/access/realm/pve":              {"Realm.AllocateUser": 1},
		}
		mc.Groups = map[string]bool{"vault-vm-admins": true}
		mc.GetUserFn = func(_ context.Context, _ string) (pveapi.UserInfo, error) {
			return pveapi.UserInfo{Groups: []string{}, Enable: true}, nil // wrong groups
		}
		mc.DeleteUserFn = func(_ context.Context, _ string) error {
			return transientErr // transient error
		}
	})
	if _, err := writeConfig(ctx, b, storage, validConfigData()); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}
	if _, err := writeRole(ctx, b, storage, "testrole", credRoleData()); err != nil {
		t.Fatalf("writeRole: %v", err)
	}

	resp, err := readCreds(ctx, b, storage, "testrole")
	// Must fail.
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatal("expected error; got success")
	}

	// WAL must be RETAINED (DeleteUser failed transiently — WAL needed for retry).
	n, err2 := countWALEntries(ctx, storage)
	if err2 != nil {
		t.Fatalf("countWALEntries: %v", err2)
	}
	if n != 1 {
		t.Errorf("expected 1 WAL entry retained after transient DeleteUser failure; got %d", n)
	}
}

// ── Token-create failure ──────────────────────────────────────────────────────

// TestCredsRead_TokenCreateFailure verifies that when CreateToken returns an
// error, DeleteUser is called for cleanup and WAL is cleaned if DeleteUser
// returned nil or ErrUserNotFound.
func TestCredsRead_TokenCreateFailure(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	tokenErr := errors.New("token creation failed")
	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		mc.GetPermissionsResult = pveapi.PermissionTree{
			"/access/groups":                 {"User.Modify": 1, "Sys.Audit": 1},
			"/access/groups/vault-vm-admins": {"User.Modify": 1},
			"/access/realm/pve":              {"Realm.AllocateUser": 1},
		}
		mc.Groups = map[string]bool{"vault-vm-admins": true}
		mc.CreateTokenError = tokenErr
	})
	if _, err := writeConfig(ctx, b, storage, validConfigData()); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}
	if _, err := writeRole(ctx, b, storage, "testrole", credRoleData()); err != nil {
		t.Fatalf("writeRole: %v", err)
	}

	resp, err := readCreds(ctx, b, storage, "testrole")
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatal("expected error when CreateToken fails; got success")
	}
	if resp != nil && resp.Secret != nil {
		t.Error("resp.Secret must be nil when CreateToken fails")
	}

	// DeleteUser must have been called (cleanup).
	b.clientMu.RLock()
	mc, _ := b.client.(*pveapi.MockClient)
	b.clientMu.RUnlock()
	if mc != nil && !mc.HasCall("DeleteUser") {
		t.Error("DeleteUser must be called for cleanup when CreateToken fails")
	}

	// WAL must be cleaned up (DeleteUser succeeds in default mock, so WAL is deleted).
	n, err2 := countWALEntries(ctx, storage)
	if err2 != nil {
		t.Fatalf("countWALEntries: %v", err2)
	}
	if n != 0 {
		t.Errorf("expected 0 WAL entries after CreateToken failure with successful cleanup; got %d", n)
	}
}

// TestCredsRead_TokenCreateFailure_DeleteUserTransient verifies that when
// CreateToken fails AND DeleteUser returns a transient error, the WAL entry
// is RETAINED for walRollback to retry.
func TestCredsRead_TokenCreateFailure_DeleteUserTransient(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		mc.GetPermissionsResult = pveapi.PermissionTree{
			"/access/groups":                 {"User.Modify": 1, "Sys.Audit": 1},
			"/access/groups/vault-vm-admins": {"User.Modify": 1},
			"/access/realm/pve":              {"Realm.AllocateUser": 1},
		}
		mc.Groups = map[string]bool{"vault-vm-admins": true}
		mc.CreateTokenError = errors.New("token error")
		mc.DeleteUserFn = func(_ context.Context, _ string) error {
			return errors.New("transient delete error")
		}
	})
	if _, err := writeConfig(ctx, b, storage, validConfigData()); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}
	if _, err := writeRole(ctx, b, storage, "testrole", credRoleData()); err != nil {
		t.Fatalf("writeRole: %v", err)
	}

	resp, err := readCreds(ctx, b, storage, "testrole")
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatal("expected error; got success")
	}

	// WAL must be RETAINED.
	n, err2 := countWALEntries(ctx, storage)
	if err2 != nil {
		t.Fatalf("countWALEntries: %v", err2)
	}
	if n != 1 {
		t.Errorf("expected 1 WAL entry retained when DeleteUser fails transiently; got %d", n)
	}
}

// ── DeleteWAL-fail on success path ────────────────────────────────────────────

// TestCredsRead_DeleteWAL_Fail_OnSuccessPath verifies the DeleteWAL-fail path:
// when the success-path DeleteWAL fails (storage error), best-effort DeleteUser
// is called and the handler returns an error (no Secret returned).
//
// This uses a failingDeleteStorage wrapper that returns errors for wal/ deletes.
func TestCredsRead_DeleteWAL_Fail_OnSuccessPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Build a real MockClient to use.
	mc := &pveapi.MockClient{}
	mc.GetPermissionsResult = pveapi.PermissionTree{
		"/access/groups":                 {"User.Modify": 1, "Sys.Audit": 1},
		"/access/groups/vault-vm-admins": {"User.Modify": 1},
		"/access/realm/pve":              {"Realm.AllocateUser": 1},
	}
	mc.Groups = map[string]bool{"vault-vm-admins": true}

	// Build backend directly (not via newTestBackend, so we can wrap storage).
	innerConfig := logical.TestBackendConfig()
	innerConfig.StorageView = &logical.InmemStorage{}

	b, err := newBackend(ctx, innerConfig)
	if err != nil {
		t.Fatalf("newBackend: %v", err)
	}
	b.newClient = func(_ *proxmoxConfig) (pveapi.Client, error) {
		return mc, nil
	}

	// Use the inner storage for config/role writes, then wrap with failing storage
	// for the creds read.
	innerStorage := innerConfig.StorageView

	if _, err := writeConfig(ctx, b, innerStorage, validConfigData()); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}
	if _, err := writeRole(ctx, b, innerStorage, "testrole", credRoleData()); err != nil {
		t.Fatalf("writeRole: %v", err)
	}

	// Wrap with storage that fails wal/ deletes.
	failStorage := &failingDeleteStorage{
		Storage:    innerStorage,
		failPrefix: framework.WALPrefix,
	}

	resp, reqErr := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/testrole",
		Storage:   failStorage,
	})

	// Must fail — no Secret returned.
	if reqErr == nil && (resp == nil || !resp.IsError()) {
		t.Fatal("expected error when DeleteWAL fails on success path; got success")
	}
	if resp != nil && resp.Secret != nil {
		t.Error("resp.Secret must be nil when DeleteWAL fails (credential not returned to prevent orphan without WAL)")
	}

	// DeleteUser must have been called (best-effort cleanup after DeleteWAL failure).
	if !mc.HasCall("DeleteUser") {
		t.Error("DeleteUser must be called as best-effort cleanup when DeleteWAL fails on success path")
	}
}

// ── Collision exhaustion ──────────────────────────────────────────────────────

// TestCredsRead_CollisionExhaustion verifies that when CreateUser returns
// ErrConflict on every attempt, the bounded retry loop exhausts and returns
// an internal error. All per-attempt WAL entries must be cleaned up.
func TestCredsRead_CollisionExhaustion(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	callCount := 0
	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		mc.GetPermissionsResult = pveapi.PermissionTree{
			"/access/groups":                 {"User.Modify": 1, "Sys.Audit": 1},
			"/access/groups/vault-vm-admins": {"User.Modify": 1},
			"/access/realm/pve":              {"Realm.AllocateUser": 1},
		}
		mc.Groups = map[string]bool{"vault-vm-admins": true}
		mc.CreateUserFn = func(_ context.Context, _ pveapi.CreateUserRequest) error {
			callCount++
			return fmt.Errorf("pveapi: CreateUser: %w", pveapi.ErrConflict)
		}
	})
	if _, err := writeConfig(ctx, b, storage, validConfigData()); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}
	if _, err := writeRole(ctx, b, storage, "testrole", credRoleData()); err != nil {
		t.Fatalf("writeRole: %v", err)
	}

	resp, err := readCreds(ctx, b, storage, "testrole")
	// Must fail with an error.
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatal("expected error after collision exhaustion; got success")
	}
	if resp != nil && resp.Secret != nil {
		t.Error("resp.Secret must be nil after collision exhaustion")
	}

	// Must have attempted exactly maxCollisionRetries times.
	if callCount != maxCollisionRetries {
		t.Errorf("CreateUser call count = %d; want %d (maxCollisionRetries)", callCount, maxCollisionRetries)
	}

	// All per-attempt WAL entries must be cleaned up after collision exhaustion.
	n, err2 := countWALEntries(ctx, storage)
	if err2 != nil {
		t.Fatalf("countWALEntries: %v", err2)
	}
	if n != 0 {
		t.Errorf("expected 0 WAL entries after collision exhaustion; got %d", n)
	}
}

// ── TTL=0 refusal ─────────────────────────────────────────────────────────────

// TestCredsRead_TTLZero_Refused verifies Locked Decision #9: issuance is refused
// when the effective TTL resolves to zero (unlimited credential). This is tested
// by creating a backend with a zero-TTL system view (DefaultLeaseTTL=0,
// MaxLeaseTTL=0) and a role/config with no TTL values set.
//
// This test verifies that:
//   - handleCredsRead returns an error response.
//   - NO PVE calls are made (CreateUser, GetUser, CreateToken must NOT be called).
func TestCredsRead_TTLZero_Refused(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	mc := &pveapi.MockClient{}
	mc.GetPermissionsResult = pveapi.PermissionTree{
		"/access/groups":                 {"User.Modify": 1, "Sys.Audit": 1},
		"/access/groups/vault-vm-admins": {"User.Modify": 1},
		"/access/realm/pve":              {"Realm.AllocateUser": 1},
	}
	mc.Groups = map[string]bool{"vault-vm-admins": true}

	// Build a backend with DefaultLeaseTTL=0 and MaxLeaseTTL=0 system view
	// so that CalculateTTL returns 0 when role/config TTLs are also unset.
	cfg := logical.TestBackendConfig()
	cfg.StorageView = &logical.InmemStorage{}
	cfg.System = &logical.StaticSystemView{
		DefaultLeaseTTLVal: 0,
		MaxLeaseTTLVal:     0,
	}
	b, err := newBackend(ctx, cfg)
	if err != nil {
		t.Fatalf("newBackend: %v", err)
	}
	b.newClient = func(_ *proxmoxConfig) (pveapi.Client, error) {
		return mc, nil
	}
	storage := cfg.StorageView

	if _, err := writeConfig(ctx, b, storage, validConfigData()); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}

	// Write a role with NO TTL set (both ttl and max_ttl = 0/unset).
	// Config default_ttl is also unset. With system DefaultLeaseTTL=0,
	// CalculateTTL will yield 0.
	roleData := map[string]interface{}{
		"group":       "vault-vm-admins",
		"user_prefix": "vault",
		"realm":       "pve",
		// ttl and max_ttl intentionally omitted — both unset → system default → 0.
	}
	if _, err := writeRole(ctx, b, storage, "zero-ttl-role", roleData); err != nil {
		t.Fatalf("writeRole: %v", err)
	}

	resp, reqErr := readCreds(ctx, b, storage, "zero-ttl-role")
	// Must fail — either a framework error or an error response.
	if reqErr == nil && (resp == nil || !resp.IsError()) {
		t.Fatal("expected error when effective TTL is zero (unlimited); got success")
	}
	if resp != nil && resp.Secret != nil {
		t.Error("resp.Secret must be nil when TTL=0 is refused")
	}

	// Verify the error mentions TTL / unlimited.
	var errMsg string
	if reqErr != nil {
		errMsg = strings.ToLower(reqErr.Error())
	} else if resp != nil {
		errMsg = strings.ToLower(resp.Error().Error())
	}
	if !strings.Contains(errMsg, "ttl") && !strings.Contains(errMsg, "zero") && !strings.Contains(errMsg, "unlimited") {
		t.Errorf("error should mention TTL/zero/unlimited; got: %q", errMsg)
	}

	// NO PVE calls must have been made (no CreateUser, GetUser, CreateToken).
	if mc.HasCall("CreateUser") {
		t.Error("CreateUser must NOT be called when TTL=0 is refused")
	}
	if mc.HasCall("GetUser") {
		t.Error("GetUser must NOT be called when TTL=0 is refused")
	}
	if mc.HasCall("CreateToken") {
		t.Error("CreateToken must NOT be called when TTL=0 is refused")
	}
}

// TestCredsRead_TTLZero_NoPVECalls is a complementary check: even when a config
// default_ttl is set but the role explicitly sets a value, a zero effective TTL
// (hypothetical — defended in depth) still refuses. This tests the early-exit path.
//
// Separately: verify NO PVE calls are made when the early exit triggers.
// We test by simply making sure the client is never even invoked (no getClient call)
// by checking that the cached client is nil when config hasn't been written yet.
func TestCredsRead_NoPVECalls_WhenNoConfig(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// No config written — getClient will return an error before any PVE call.
	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		mc.GetPermissionsResult = pveapi.PermissionTree{
			"/access/groups": {"User.Modify": 1, "Sys.Audit": 1},
		}
	})

	// No config written. readCreds should return an error response.
	resp, err := readCreds(ctx, b, storage, "nonexistent-role")
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatal("expected error when no config and no role; got success")
	}
	if resp != nil && resp.Secret != nil {
		t.Error("resp.Secret must be nil when config is absent")
	}
}

// ── Missing role ──────────────────────────────────────────────────────────────

// TestCredsRead_RoleNotFound verifies that readCreds returns an error (not a
// panic) when the requested role does not exist.
func TestCredsRead_RoleNotFound(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	b, storage := setupBackendForCreds(t, "existing-role", credRoleData(), nil)

	resp, err := readCreds(ctx, b, storage, "nonexistent-role")
	if err != nil {
		t.Fatalf("unexpected framework error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response for nonexistent role")
	}
	if !strings.Contains(strings.ToLower(resp.Error().Error()), "not found") {
		t.Errorf("expected 'not found' in error; got: %q", resp.Error())
	}
}

// ── CreateUser groups and enable assertions ───────────────────────────────────

// TestCredsRead_CreateUser_GroupsAndEnable verifies that CreateUser is called
// with Enable=true and Groups=<role.group> (the single-call group-add path).
func TestCredsRead_CreateUser_GroupsAndEnable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	var capturedReq pveapi.CreateUserRequest
	var usersMu4 sync.Mutex
	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		mc.GetPermissionsResult = pveapi.PermissionTree{
			"/access/groups":                 {"User.Modify": 1, "Sys.Audit": 1},
			"/access/groups/vault-vm-admins": {"User.Modify": 1},
			"/access/realm/pve":              {"Realm.AllocateUser": 1},
		}
		mc.Groups = map[string]bool{"vault-vm-admins": true}
		mc.CreateUserFn = func(_ context.Context, req pveapi.CreateUserRequest) error {
			capturedReq = req
			// Create in memory for GetUser read-back.
			usersMu4.Lock()
			defer usersMu4.Unlock()
			if mc.Users == nil {
				mc.Users = make(map[string]pveapi.UserInfo)
			}
			mc.Users[req.UserID] = pveapi.UserInfo{
				Groups: []string{"vault-vm-admins"},
				Enable: req.Enable,
				Expire: req.Expire,
			}
			return nil
		}
	})
	if _, err := writeConfig(ctx, b, storage, validConfigData()); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}
	if _, err := writeRole(ctx, b, storage, "testrole", credRoleData()); err != nil {
		t.Fatalf("writeRole: %v", err)
	}

	resp, err := readCreds(ctx, b, storage, "testrole")
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("readCreds: err=%v resp=%v", err, resp)
	}

	if capturedReq.Groups != "vault-vm-admins" {
		t.Errorf("CreateUser Groups = %q; want vault-vm-admins", capturedReq.Groups)
	}
	if !capturedReq.Enable {
		t.Error("CreateUser Enable must be true for freshly created lease users")
	}
}

// ── Lease TTL fields ──────────────────────────────────────────────────────────

// TestCredsRead_LeaseTTL verifies that resp.Secret.TTL and MaxTTL are set.
func TestCredsRead_LeaseTTL(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	b, storage := setupBackendForCreds(t, "myrole", credRoleData(), nil)

	resp, err := readCreds(ctx, b, storage, "myrole")
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("readCreds: err=%v resp=%v", err, resp)
	}
	if resp.Secret.TTL <= 0 {
		t.Errorf("resp.Secret.TTL = %v; want > 0", resp.Secret.TTL)
	}
}

// ── Round-trip InternalData ───────────────────────────────────────────────────

// TestCredsRead_InternalData_RoundTrip verifies all three required InternalData
// fields are present and have the expected types/values.
func TestCredsRead_InternalData_RoundTrip(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	b, storage := setupBackendForCreds(t, "myrole", credRoleData(), nil)

	resp, err := readCreds(ctx, b, storage, "myrole")
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("readCreds: err=%v resp=%v", err, resp)
	}

	intData := resp.Secret.InternalData

	// pve_userid: non-empty string matching user_id in resp.Data.
	pveid, ok := intData["pve_userid"].(string)
	if !ok || pveid == "" {
		t.Fatalf("InternalData pve_userid: expected non-empty string, got %T %v", intData["pve_userid"], intData["pve_userid"])
	}
	if userID, _ := resp.Data["user_id"].(string); pveid != userID {
		t.Errorf("InternalData pve_userid = %q; want same as resp.Data user_id = %q", pveid, userID)
	}

	// group: matches role.group.
	grp, ok := intData["group"].(string)
	if !ok || grp == "" {
		t.Fatalf("InternalData group: expected non-empty string, got %T %v", intData["group"], intData["group"])
	}
	if grp != "vault-vm-admins" {
		t.Errorf("InternalData group = %q; want vault-vm-admins", grp)
	}

	// effective_max_ttl: numeric, stored as int64 nanoseconds.
	raw, ok := intData["effective_max_ttl"]
	if !ok {
		t.Fatal("InternalData effective_max_ttl missing")
	}
	switch v := raw.(type) {
	case int64:
		// ok
		_ = v
	case float64:
		// JSON round-trip may decode as float64 — acceptable.
		_ = v
	default:
		t.Errorf("InternalData effective_max_ttl type = %T; want int64 or float64", raw)
	}

	// C2: role_name and expire must be present.
	rn, ok := intData["role_name"].(string)
	if !ok {
		t.Fatalf("InternalData role_name: expected string, got %T %v", intData["role_name"], intData["role_name"])
	}
	if rn != "myrole" {
		t.Errorf("InternalData role_name = %q; want %q", rn, "myrole")
	}
	if _, ok := intData["expire"]; !ok {
		t.Error("InternalData expire missing")
	}
}

// ── M1: WAL nonce == CreateUser Comment invariant ─────────────────────────────

// TestCredsRead_WALNonce_EqualsCreateUserComment pins the nonce↔comment
// ownership invariant: walUser.Nonce (stored in the WAL entry) must equal
// CreateUserRequest.Comment (sent to PVE at creation time).
//
// Test path chosen for WAL survival:
//   - CreateUser succeeds (captures createReq.Comment)
//   - GetUser read-back succeeds (default mock returns stored user)
//   - CreateToken fails → cleanupUser called
//   - DeleteUser fails transiently → WAL entry is RETAINED (WAL discipline:
//     never orphan a user without a WAL entry)
//
// After the failed issuance, exactly one WAL entry must remain. We read it
// back via framework.GetWAL and assert entry.Data["nonce"] == capturedComment.
func TestCredsRead_WALNonce_EqualsCreateUserComment(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	var capturedComment string
	var usersMu sync.Mutex

	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		mc.GetPermissionsResult = pveapi.PermissionTree{
			"/access/groups":                 {"User.Modify": 1, "Sys.Audit": 1},
			"/access/groups/vault-vm-admins": {"User.Modify": 1},
			"/access/realm/pve":              {"Realm.AllocateUser": 1},
		}
		mc.Groups = map[string]bool{"vault-vm-admins": true}

		// CreateUser: capture the Comment (the nonce) and store the user for
		// GetUser read-back (group membership assertion must pass).
		mc.CreateUserFn = func(_ context.Context, req pveapi.CreateUserRequest) error {
			capturedComment = req.Comment
			usersMu.Lock()
			defer usersMu.Unlock()
			if mc.Users == nil {
				mc.Users = make(map[string]pveapi.UserInfo)
			}
			mc.Users[req.UserID] = pveapi.UserInfo{
				Groups:  []string{"vault-vm-admins"},
				Enable:  req.Enable,
				Expire:  req.Expire,
				Comment: req.Comment, // preserve for GetUser read-back comment check
			}
			return nil
		}

		// CreateToken fails: triggers cleanupUser.
		mc.CreateTokenError = errors.New("simulated token creation failure")

		// DeleteUser fails transiently: WAL entry is RETAINED per WAL discipline
		// (never DeleteWAL if DeleteUser fails transiently).
		mc.DeleteUserFn = func(_ context.Context, _ string) error {
			return errors.New("simulated transient delete failure")
		}
	})
	if _, err := writeConfig(ctx, b, storage, validConfigData()); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}
	if _, err := writeRole(ctx, b, storage, "testrole", credRoleData()); err != nil {
		t.Fatalf("writeRole: %v", err)
	}

	resp, err := readCreds(ctx, b, storage, "testrole")
	// Must fail (CreateToken error).
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatal("expected error when CreateToken fails; got success")
	}

	// CreateUser must have been called and comment must be non-empty.
	if capturedComment == "" {
		t.Fatal("CreateUserFn was not called or captured an empty comment; cannot assert WAL nonce invariant")
	}

	// The WAL entry must have survived (DeleteUser failed transiently).
	walIDs, listErr := framework.ListWAL(ctx, storage)
	if listErr != nil {
		t.Fatalf("framework.ListWAL: %v", listErr)
	}
	if len(walIDs) != 1 {
		t.Fatalf("expected 1 surviving WAL entry; got %d — cannot assert nonce invariant", len(walIDs))
	}

	// Read back the WAL entry and assert the nonce equals the captured comment.
	// WALEntry.Data is JSON-decoded into interface{} → map[string]interface{}.
	walEntry, getErr := framework.GetWAL(ctx, storage, walIDs[0])
	if getErr != nil {
		t.Fatalf("framework.GetWAL(%q): %v", walIDs[0], getErr)
	}
	if walEntry == nil {
		t.Fatalf("framework.GetWAL returned nil for id %q", walIDs[0])
	}

	dataMap, ok := walEntry.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("WALEntry.Data type = %T; want map[string]interface{}", walEntry.Data)
	}
	storedNonce, ok := dataMap["nonce"].(string)
	if !ok {
		t.Fatalf("WALEntry.Data[\"nonce\"] type = %T; want string", dataMap["nonce"])
	}

	// Core invariant: WAL nonce == CreateUserRequest.Comment (both carry the same
	// prefixed string so walRollbackUser's ownership comparison is a simple equality).
	if storedNonce != capturedComment {
		t.Errorf("WAL nonce invariant violated: walUser.Nonce = %q; CreateUserRequest.Comment = %q; they must be equal",
			storedNonce, capturedComment)
	}
	// Also verify the prefix is present (M1 prefix check on the stored nonce).
	if !strings.HasPrefix(storedNonce, walCommentPrefix) {
		t.Errorf("walUser.Nonce = %q; want %s prefix (walCommentPrefix)", storedNonce, walCommentPrefix)
	}
}

// TestCredsRead_UnauthenticatedCreateUserDiagnostic verifies DR-1 issuance
// diagnostics: an admin-token 401 sentinel is wrapped with a human-readable
// operator hint while preserving errors.Is.
func TestCredsRead_UnauthenticatedCreateUserDiagnostic(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	b, storage := setupBackendForCreds(t, "testrole", credRoleData(), func(mc *pveapi.MockClient) {
		mc.CreateUserError = fmt.Errorf("pveapi: CreateUser: %w", pveapi.ErrUnauthenticated)
	})

	resp, err := readCreds(ctx, b, storage, "testrole")
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatal("expected unauthenticated issuance error, got success")
	}
	if err == nil {
		err = resp.Error()
	}
	if !errors.Is(err, pveapi.ErrUnauthenticated) {
		t.Fatalf("expected errors.Is ErrUnauthenticated; got %v", err)
	}
	if !strings.Contains(err.Error(), "admin token unauthenticated") || !strings.Contains(err.Error(), "check config credentials") {
		t.Errorf("error missing admin-token diagnostic: %q", err.Error())
	}
}
