// Package proxmox — unit tests for wal.go.
//
// Covers walRollback and walRollbackUser:
//   - map[string]interface{} payload decodes correctly into walUser.
//   - DeleteUser success → walRollback returns nil.
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
	}
	if !strings.Contains(err.Error(), "unknown-kind-xyz") {
		t.Errorf("error should mention the unknown kind; got: %q", err)
	}
}

// TestWALRollback_MapPayloadDecodes verifies that a map[string]interface{}
// payload (the format returned by framework.GetWAL after JSON round-trip)
// decodes correctly into walUser via mapstructure.
//
// This is the exact format the SDK delivers to walRollback: WALEntry.Data
// is JSON-decoded into interface{} → map[string]interface{}.
func TestWALRollback_MapPayloadDecodes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	var deletedUserID string
	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		mc.DeleteUserFn = func(_ context.Context, userid string) error {
			deletedUserID = userid
			return nil
		}
	})
	if _, err := writeConfig(ctx, b, storage, validConfigData()); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}

	// Simulate the JSON round-trip: walUser → JSON → map[string]interface{}.
	payload := map[string]interface{}{
		"user_id": "vault-myrole-a3b7x2kp@pve",
	}

	req := makeWALRequest(storage)
	err := b.walRollback(ctx, req, walTypeUser, payload)
	if err != nil {
		t.Fatalf("walRollback: unexpected error: %v", err)
	}
	if deletedUserID != "vault-myrole-a3b7x2kp@pve" {
		t.Errorf("DeleteUser called with %q; want vault-myrole-a3b7x2kp@pve", deletedUserID)
	}
}

// TestWALRollback_DeleteUser_Success verifies that a successful DeleteUser
// causes walRollback to return nil.
func TestWALRollback_DeleteUser_Success(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	deleteCalled := false
	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		mc.DeleteUserFn = func(_ context.Context, _ string) error {
			deleteCalled = true
			return nil
		}
	})
	if _, err := writeConfig(ctx, b, storage, validConfigData()); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}

	payload := map[string]interface{}{"user_id": "vault-role-abc12345@pve"}
	req := makeWALRequest(storage)
	if err := b.walRollback(ctx, req, walTypeUser, payload); err != nil {
		t.Fatalf("walRollback: unexpected error: %v", err)
	}
	if !deleteCalled {
		t.Error("expected DeleteUser to be called; it was not")
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

	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		mc.DeleteUserFn = func(_ context.Context, _ string) error {
			// Simulate PVE HTTP 500 + body "no such user"
			return fmt.Errorf("pveapi: DeleteUser: %w", pveapi.ErrUserNotFound)
		}
	})
	if _, err := writeConfig(ctx, b, storage, validConfigData()); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}

	payload := map[string]interface{}{"user_id": "vault-role-abc12345@pve"}
	req := makeWALRequest(storage)
	err := b.walRollback(ctx, req, walTypeUser, payload)
	if err != nil {
		t.Fatalf("walRollback: expected nil for ErrUserNotFound; got: %v", err)
	}
}

// TestWALRollback_TransientError_ReturnsError verifies that when DeleteUser
// returns a transient/non-ErrUserNotFound error, walRollback returns that error
// so the SDK retries on the next rollback sweep and the WAL entry is NOT deleted.
func TestWALRollback_TransientError_ReturnsError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	transientErr := errors.New("network timeout")
	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		mc.DeleteUserFn = func(_ context.Context, _ string) error {
			return transientErr
		}
	})
	if _, err := writeConfig(ctx, b, storage, validConfigData()); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}

	payload := map[string]interface{}{"user_id": "vault-role-abc12345@pve"}
	req := makeWALRequest(storage)
	err := b.walRollback(ctx, req, walTypeUser, payload)
	if err == nil {
		t.Fatal("expected error for transient DeleteUser failure; got nil")
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

	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		mc.DeleteUserFn = func(_ context.Context, _ string) error {
			return fmt.Errorf("pveapi: DeleteUser: %w", pveapi.ErrForbidden)
		}
	})
	if _, err := writeConfig(ctx, b, storage, validConfigData()); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}

	payload := map[string]interface{}{"user_id": "vault-role-abc12345@pve"}
	req := makeWALRequest(storage)
	err := b.walRollback(ctx, req, walTypeUser, payload)
	if err == nil {
		t.Fatal("expected error for ErrForbidden from DeleteUser; got nil")
	}
}

// TestWALRollback_EmptyUserID_ReturnsError verifies that a WAL payload with
// an empty user_id is rejected before any PVE call is made.
func TestWALRollback_EmptyUserID_ReturnsError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	deleteCalled := false
	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
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
	}
}
