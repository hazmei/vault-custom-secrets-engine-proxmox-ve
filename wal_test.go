// Package proxmox — unit tests for wal.go.
//
// Covers walRollback and walRollbackUser:
//   - map[string]interface{} payload decodes correctly into walUser.
//   - Nonce matches user comment → DeleteUser called, returns nil.
//   - Nonce mismatch (foreign user) → DeleteUser NOT called, returns nil (WAL dropped).
//   - GetUser returns ErrUserNotFound → returns nil, DeleteUser not called.
//   - GetUser transient error → returns error (WAL retained for retry).
//   - DeleteUser success (nonce match) → walRollback returns nil.
//   - DeleteUser returns ErrUserNotFound (PVE body "no such user", HTTP 500) →
//     walRollback returns nil (idempotent success).
//   - DeleteUser returns a transient/other error → walRollback returns that error
//     (SDK retries; WAL left).
//   - Unknown WAL kind → walRollback returns an error.
package proxmox

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	pveapi "github.com/hazmei/vault-plugin-secrets-proxmox/internal/pveapi"
)

// ── walRollback helpers ───────────────────────────────────────────────────────

// makeWALRequest builds a minimal *logical.Request with in-memory storage.
// walRollback uses req.Storage to get the PVE client via getClient.
func makeWALRequest(storage logical.Storage) *logical.Request {
	return &logical.Request{
		Storage: storage,
	}
}

// walPayloadWithNonce returns a WAL payload map containing both user_id and nonce.
func walPayloadWithNonce(userid, nonce string) map[string]interface{} {
	return map[string]interface{}{
		"user_id": userid,
		"nonce":   nonce,
	}
}

// ── walRollback tests ─────────────────────────────────────────────────────────

// TestWALRollback_UnknownKind verifies that walRollback returns an error for
// an unrecognised WAL kind. This guards against silently swallowing unknown
// entries (operators see the error in the Vault audit log).
func TestWALRollback_UnknownKind(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	b, storage := newTestBackend(t, defaultMock())
	// Write config so getClient can succeed (walRollback calls getClient).
	if _, err := writeConfig(ctx, b, storage, validConfigData()); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}

	req := makeWALRequest(storage)
	err := b.walRollback(ctx, req, "unknown-kind-xyz", map[string]interface{}{})
	if err == nil {
		t.Fatal("expected error for unknown WAL kind; got nil")
		return
	}
	if !strings.Contains(err.Error(), "unknown-kind-xyz") {
		t.Errorf("error should mention the unknown kind; got: %q", err)
	}
}

// TestWALRollback_MapPayloadDecodes verifies that a map[string]interface{}
// payload (the format returned by framework.GetWAL after JSON round-trip)
// decodes correctly into walUser via mapstructure, and that when the nonce
// matches the user's comment, the user is deleted.
//
// This is the exact format the SDK delivers to walRollback: WALEntry.Data
// is JSON-decoded into interface{} → map[string]interface{}.
func TestWALRollback_MapPayloadDecodes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	const (
		userid = "vault-myrole-a3b7x2kp@pve"
		nonce  = "testnonce1"
	)

	var deletedUserID string
	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		// GetUser returns the user with comment matching the nonce.
		mc.GetUserFn = func(_ context.Context, uid string) (pveapi.UserInfo, error) {
			return pveapi.UserInfo{
				Groups:  []string{"vault-grp"},
				Enable:  true,
				Comment: nonce,
			}, nil
		}
		mc.DeleteUserFn = func(_ context.Context, uid string) error {
			deletedUserID = uid
			return nil
		}
	})
	if _, err := writeConfig(ctx, b, storage, validConfigData()); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}

	// Simulate the JSON round-trip: walUser → JSON → map[string]interface{}.
	payload := walPayloadWithNonce(userid, nonce)

	req := makeWALRequest(storage)
	err := b.walRollback(ctx, req, walTypeUser, payload)
	if err != nil {
		t.Fatalf("walRollback: unexpected error: %v", err)
	}
	if deletedUserID != userid {
		t.Errorf("DeleteUser called with %q; want %q", deletedUserID, userid)
	}
}

// TestWALRollback_DeleteUser_Success verifies that a successful DeleteUser
// (after nonce/comment ownership verification) causes walRollback to return nil.
func TestWALRollback_DeleteUser_Success(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	const (
		userid = "vault-role-abc12345@pve"
		nonce  = "sucnonce22"
	)

	deleteCalled := false
	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		mc.GetUserFn = func(_ context.Context, _ string) (pveapi.UserInfo, error) {
			return pveapi.UserInfo{Comment: nonce, Enable: true}, nil
		}
		mc.DeleteUserFn = func(_ context.Context, _ string) error {
			deleteCalled = true
			return nil
		}
	})
	if _, err := writeConfig(ctx, b, storage, validConfigData()); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}

	payload := walPayloadWithNonce(userid, nonce)
	req := makeWALRequest(storage)
	if err := b.walRollback(ctx, req, walTypeUser, payload); err != nil {
		t.Fatalf("walRollback: unexpected error: %v", err)
	}
	if !deleteCalled {
		t.Error("expected DeleteUser to be called; it was not")
	}
}

// TestWALRollback_GetUserNotFound_IsIdempotentSuccess verifies that when
// GetUser returns ErrUserNotFound (user already absent), walRollback treats
// it as success and returns nil without calling DeleteUser.
func TestWALRollback_GetUserNotFound_IsIdempotentSuccess(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	deleteCalled := false
	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		mc.GetUserFn = func(_ context.Context, _ string) (pveapi.UserInfo, error) {
			// User is already absent.
			return pveapi.UserInfo{}, fmt.Errorf("pveapi: GetUser: %w", pveapi.ErrUserNotFound)
		}
		mc.DeleteUserFn = func(_ context.Context, _ string) error {
			deleteCalled = true
			return nil
		}
	})
	if _, err := writeConfig(ctx, b, storage, validConfigData()); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}

	payload := walPayloadWithNonce("vault-role-absent@pve", "anynonce33")
	req := makeWALRequest(storage)
	err := b.walRollback(ctx, req, walTypeUser, payload)
	if err != nil {
		t.Fatalf("walRollback: expected nil for ErrUserNotFound on GetUser; got: %v", err)
	}
	if deleteCalled {
		t.Error("DeleteUser must NOT be called when GetUser returns ErrUserNotFound")
	}
}

// TestWALRollback_ErrUserNotFound_IsIdempotentSuccess verifies that when
// DeleteUser returns ErrUserNotFound (PVE HTTP 500 + body "no such user"),
// walRollback treats it as success and returns nil.
//
// This is the idempotency requirement: if the user is already absent (e.g. was
// cleaned up by a prior successful revocation), walRollback must succeed so the
// framework removes the WAL entry.
func TestWALRollback_ErrUserNotFound_IsIdempotentSuccess(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	const nonce = "idemnonce44"

	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		mc.GetUserFn = func(_ context.Context, _ string) (pveapi.UserInfo, error) {
			// User exists with matching comment — ownership verified.
			return pveapi.UserInfo{Comment: nonce, Enable: true}, nil
		}
		mc.DeleteUserFn = func(_ context.Context, _ string) error {
			// Simulate PVE HTTP 500 + body "no such user" (race: already deleted).
			return fmt.Errorf("pveapi: DeleteUser: %w", pveapi.ErrUserNotFound)
		}
	})
	if _, err := writeConfig(ctx, b, storage, validConfigData()); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}

	payload := walPayloadWithNonce("vault-role-abc12345@pve", nonce)
	req := makeWALRequest(storage)
	err := b.walRollback(ctx, req, walTypeUser, payload)
	if err != nil {
		t.Fatalf("walRollback: expected nil for ErrUserNotFound; got: %v", err)
	}
}

// TestWALRollback_NonceMismatch_ForeignUser_DropsWALWithoutDelete verifies the
// ownership check: when the user's comment does NOT match the WAL nonce (foreign
// user / pre-existing collision), walRollback returns nil (drops the WAL entry)
// WITHOUT calling DeleteUser, preventing deletion of a user we don't own.
func TestWALRollback_NonceMismatch_ForeignUser_DropsWALWithoutDelete(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	deleteCalled := false
	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		mc.GetUserFn = func(_ context.Context, _ string) (pveapi.UserInfo, error) {
			// User exists but has a DIFFERENT comment — foreign user.
			return pveapi.UserInfo{Comment: "some-other-comment", Enable: true}, nil
		}
		mc.DeleteUserFn = func(_ context.Context, _ string) error {
			deleteCalled = true
			return nil
		}
	})
	if _, err := writeConfig(ctx, b, storage, validConfigData()); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}

	payload := walPayloadWithNonce("vault-role-foreign@pve", "my-nonce-xyz")
	req := makeWALRequest(storage)
	err := b.walRollback(ctx, req, walTypeUser, payload)
	// Must return nil so the framework drops the WAL entry.
	if err != nil {
		t.Fatalf("walRollback: expected nil for nonce mismatch (foreign user); got: %v", err)
	}
	// DeleteUser must NOT have been called.
	if deleteCalled {
		t.Error("DeleteUser must NOT be called when nonce mismatch (foreign user); WAL must be dropped without deleting")
	}
}

// TestWALRollback_EmptyNonce_ForeignUser_DropsWALWithoutDelete verifies that
// an empty nonce in the WAL entry also triggers the foreign-user guard (does not
// delete). This covers old WAL entries written before the nonce field was added
// that have colliding userids with pre-existing users.
func TestWALRollback_EmptyNonce_ForeignUser_DropsWALWithoutDelete(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	deleteCalled := false
	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		mc.GetUserFn = func(_ context.Context, _ string) (pveapi.UserInfo, error) {
			// User exists (could be foreign).
			return pveapi.UserInfo{Comment: "some-comment", Enable: true}, nil
		}
		mc.DeleteUserFn = func(_ context.Context, _ string) error {
			deleteCalled = true
			return nil
		}
	})
	if _, err := writeConfig(ctx, b, storage, validConfigData()); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}

	// Payload with empty nonce (old-format WAL entry, no nonce field).
	payload := map[string]interface{}{"user_id": "vault-role-oldwal@pve"}
	req := makeWALRequest(storage)
	err := b.walRollback(ctx, req, walTypeUser, payload)
	if err != nil {
		t.Fatalf("walRollback: expected nil for empty nonce (old WAL); got: %v", err)
	}
	if deleteCalled {
		t.Error("DeleteUser must NOT be called for empty nonce WAL entry (guards against deleting foreign user)")
	}
}

// TestWALRollback_GetUserTransientError_ReturnsError verifies that when GetUser
// returns a transient (non-ErrUserNotFound) error, walRollback returns the error
// so the SDK retries on the next rollback sweep. WAL entry is retained.
func TestWALRollback_GetUserTransientError_ReturnsError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	transientErr := errors.New("network timeout on GetUser")
	deleteCalled := false
	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		mc.GetUserFn = func(_ context.Context, _ string) (pveapi.UserInfo, error) {
			return pveapi.UserInfo{}, transientErr
		}
		mc.DeleteUserFn = func(_ context.Context, _ string) error {
			deleteCalled = true
			return nil
		}
	})
	if _, err := writeConfig(ctx, b, storage, validConfigData()); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}

	payload := walPayloadWithNonce("vault-role-gettransient@pve", "gettransientnonce")
	req := makeWALRequest(storage)
	err := b.walRollback(ctx, req, walTypeUser, payload)
	if err == nil {
		t.Fatal("expected error for transient GetUser failure; got nil")
		return
	}
	if !errors.Is(err, transientErr) {
		t.Errorf("expected error to wrap transientErr; got: %v", err)
	}
	if deleteCalled {
		t.Error("DeleteUser must NOT be called when GetUser returns a transient error")
	}
}

// TestWALRollback_TransientError_ReturnsError verifies that when GetUser succeeds
// (nonce matches) but DeleteUser returns a transient/non-ErrUserNotFound error,
// walRollback returns that error so the SDK retries on the next rollback sweep.
func TestWALRollback_TransientError_ReturnsError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	const nonce = "transientnonce55"
	transientErr := errors.New("network timeout")
	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		mc.GetUserFn = func(_ context.Context, _ string) (pveapi.UserInfo, error) {
			return pveapi.UserInfo{Comment: nonce, Enable: true}, nil
		}
		mc.DeleteUserFn = func(_ context.Context, _ string) error {
			return transientErr
		}
	})
	if _, err := writeConfig(ctx, b, storage, validConfigData()); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}

	payload := walPayloadWithNonce("vault-role-abc12345@pve", nonce)
	req := makeWALRequest(storage)
	err := b.walRollback(ctx, req, walTypeUser, payload)
	if err == nil {
		t.Fatal("expected error for transient DeleteUser failure; got nil")
		return
	}
	if !errors.Is(err, transientErr) {
		t.Errorf("expected error to wrap transientErr; got: %v", err)
	}
}

// TestWALRollback_ErrForbidden_ReturnsError verifies that a 403 ErrForbidden
// from DeleteUser (not ErrUserNotFound) causes walRollback to return an error.
// The WAL entry must be retained so the operator can investigate.
func TestWALRollback_ErrForbidden_ReturnsError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	const nonce = "forbiddennonce66"
	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		mc.GetUserFn = func(_ context.Context, _ string) (pveapi.UserInfo, error) {
			return pveapi.UserInfo{Comment: nonce, Enable: true}, nil
		}
		mc.DeleteUserFn = func(_ context.Context, _ string) error {
			return fmt.Errorf("pveapi: DeleteUser: %w", pveapi.ErrForbidden)
		}
	})
	if _, err := writeConfig(ctx, b, storage, validConfigData()); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}

	payload := walPayloadWithNonce("vault-role-abc12345@pve", nonce)
	req := makeWALRequest(storage)
	err := b.walRollback(ctx, req, walTypeUser, payload)
	if err == nil {
		t.Fatal("expected error for ErrForbidden from DeleteUser; got nil")
		return
	}
}

// TestWALRollback_EmptyUserID_ReturnsError verifies that a WAL payload with
// an empty user_id is rejected before any PVE call is made.
func TestWALRollback_EmptyUserID_ReturnsError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	getUserCalled := false
	deleteCalled := false
	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		mc.GetUserFn = func(_ context.Context, _ string) (pveapi.UserInfo, error) {
			getUserCalled = true
			return pveapi.UserInfo{}, nil
		}
		mc.DeleteUserFn = func(_ context.Context, _ string) error {
			deleteCalled = true
			return nil
		}
	})
	if _, err := writeConfig(ctx, b, storage, validConfigData()); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}

	payload := map[string]interface{}{"user_id": ""}
	req := makeWALRequest(storage)
	err := b.walRollback(ctx, req, walTypeUser, payload)
	if err == nil {
		t.Fatal("expected error for empty user_id; got nil")
		return
	}
	if getUserCalled {
		t.Error("GetUser must NOT be called for empty user_id WAL payload")
	}
	if deleteCalled {
		t.Error("DeleteUser must NOT be called for empty user_id WAL payload")
	}
}

// TestWALRollback_MissingUserIDKey_ReturnsError verifies that a WAL payload
// missing the user_id key is rejected (defensive: mapstructure will set an
// empty string which the empty-check then catches).
func TestWALRollback_MissingUserIDKey_ReturnsError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	b, storage := newTestBackend(t, defaultMock())
	if _, err := writeConfig(ctx, b, storage, validConfigData()); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}

	// Payload completely missing user_id.
	payload := map[string]interface{}{}
	req := makeWALRequest(storage)
	err := b.walRollback(ctx, req, walTypeUser, payload)
	if err == nil {
		t.Fatal("expected error for payload missing user_id; got nil")
		return
	}
}
