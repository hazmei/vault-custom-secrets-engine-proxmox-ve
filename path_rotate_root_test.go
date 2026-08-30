package proxmox

import (
	"context"
	"errors"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hazmei/vault-plugin-secrets-proxmox/internal/pveapi"
)

func TestRotateRootRequiresExclusiveAcknowledgement(t *testing.T) {
	b, storage := newTestBackend(t, defaultMock())
	resp, err := b.HandleRequest(context.Background(), &logical.Request{Operation: logical.UpdateOperation, Path: "rotate-root", Storage: storage, Data: map[string]interface{}{
		"expected_token_id": "vault-admin@pve!mytoken",
		"confirm_exclusive": false,
	}})
	if err != nil || resp == nil || !resp.IsError() {
		t.Fatalf("expected acknowledgement error, response=%v err=%v", resp, err)
	}
}

func TestRotateRootPersistsReplacementBeforeDeletingOldToken(t *testing.T) {
	var calls []string
	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		mc.GetPermissionsResult = pveapi.PermissionTree{"/access/groups": {"User.Modify": 1, "Sys.Audit": 1}}
		mc.DeleteTokenFn = func(_ context.Context, _, _ string) error {
			calls = append(calls, "delete")
			return nil
		}
		mc.TokenExistsFn = func(_ context.Context, _, _ string) (bool, error) {
			calls = append(calls, "confirm")
			return false, nil
		}
	})
	if _, err := writeConfig(context.Background(), b, storage, validConfigData()); err != nil {
		t.Fatal(err)
	}
	resp, err := b.HandleRequest(context.Background(), &logical.Request{Operation: logical.UpdateOperation, Path: "rotate-root", Storage: storage, Data: map[string]interface{}{
		"expected_token_id": "vault-admin@pve!mytoken",
		"confirm_exclusive": true,
	}})
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("rotation failed: response=%v err=%v", resp, err)
	}
	if len(calls) != 2 || calls[0] != "delete" || calls[1] != "confirm" {
		t.Fatalf("deletion calls=%v, want delete then confirm", calls)
	}
	cfg, err := getConfig(context.Background(), storage)
	if err != nil || cfg.TokenID == "vault-admin@pve!mytoken" || cfg.TokenSecret != "mock-token-secret" {
		t.Fatalf("replacement config was not persisted: cfg=%+v err=%v", cfg, err)
	}
	if entry, getErr := storage.Get(context.Background(), rotationStorageKey); getErr != nil || entry != nil {
		t.Fatalf("rotation state was not cleared: entry=%v err=%v", entry, getErr)
	}
	if _, ok := resp.Data["token_secret"]; ok {
		t.Fatal("rotation response must not contain token_secret")
	}
}

func TestRotateRootAcceptsIdempotentDeleteWhenReadConfirmsAbsence(t *testing.T) {
	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		mc.DeleteTokenFn = func(context.Context, string, string) error { return pveapi.ErrTokenNotFound }
		mc.TokenExistsFn = func(context.Context, string, string) (bool, error) { return false, nil }
	})
	if _, err := writeConfig(context.Background(), b, storage, validConfigData()); err != nil {
		t.Fatal(err)
	}
	resp, err := b.HandleRequest(context.Background(), &logical.Request{Operation: logical.UpdateOperation, Path: "rotate-root", Storage: storage, Data: map[string]interface{}{
		"expected_token_id": "vault-admin@pve!mytoken", "confirm_exclusive": true,
	}})
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("idempotent rotation failed: response=%v err=%v", resp, err)
	}
}

func TestRotateRootCreateFailureRetainsRecoveryState(t *testing.T) {
	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		mc.CreateTokenError = errors.New("create failed")
	})
	if _, err := writeConfig(context.Background(), b, storage, validConfigData()); err != nil {
		t.Fatal(err)
	}
	_, err := b.HandleRequest(context.Background(), &logical.Request{Operation: logical.UpdateOperation, Path: "rotate-root", Storage: storage, Data: map[string]interface{}{
		"expected_token_id": "vault-admin@pve!mytoken", "confirm_exclusive": true,
	}})
	if err == nil {
		t.Fatal("rotation should fail when replacement creation fails")
	}
	if entry, getErr := storage.Get(context.Background(), rotationStorageKey); getErr != nil || entry == nil {
		t.Fatalf("rotation state was not retained: entry=%v err=%v", entry, getErr)
	}
}

func TestRotateRootRejectsStaleExpectedTokenID(t *testing.T) {
	b, storage := newTestBackend(t, defaultMock())
	if _, err := writeConfig(context.Background(), b, storage, validConfigData()); err != nil {
		t.Fatal(err)
	}
	resp, err := b.HandleRequest(context.Background(), &logical.Request{Operation: logical.UpdateOperation, Path: "rotate-root", Storage: storage, Data: map[string]interface{}{
		"expected_token_id": "vault-admin@pve!stale",
		"confirm_exclusive": true,
	}})
	if err != nil || resp == nil || !resp.IsError() {
		t.Fatalf("expected stale-token error, response=%v err=%v", resp, err)
	}
}

func TestRotateRootRecoveryDeletesReplacementWithOldConfig(t *testing.T) {
	var deleted string
	mc := &pveapi.MockClient{DeleteTokenFn: func(_ context.Context, _, token string) error { deleted = token; return nil }}
	b, storage := newTestBackend(t, nil)
	b.newClient = func(_ *proxmoxConfig) (pveapi.Client, error) { return mc, nil }
	if _, err := writeConfig(context.Background(), b, storage, validConfigData()); err != nil {
		t.Fatal(err)
	}
	data := map[string]interface{}{"old_token_id": "vault-admin@pve!mytoken", "new_token_id": "vault-admin@pve!replacement"}
	if err := b.walRollback(context.Background(), &logical.Request{Storage: storage}, walTypeRotation, data); err != nil {
		t.Fatalf("recovery failed: %v", err)
	}
	if deleted != "replacement" {
		t.Fatalf("recovery deleted %q, want replacement", deleted)
	}
}

func TestRotateRootRecoveryPreservesInconsistentState(t *testing.T) {
	b, storage := newTestBackend(t, defaultMock())
	if _, err := writeConfig(context.Background(), b, storage, validConfigData()); err != nil {
		t.Fatal(err)
	}
	state := rotationState{OldTokenID: "vault-admin@pve!old", NewTokenID: "vault-admin@pve!new"}
	if err := putRotationState(context.Background(), storage, state); err != nil {
		t.Fatal(err)
	}
	err := b.walRollback(context.Background(), &logical.Request{Storage: storage}, walTypeRotation, map[string]interface{}{
		"old_token_id": "vault-admin@pve!old", "new_token_id": "vault-admin@pve!new",
	})
	if err == nil {
		t.Fatal("inconsistent rotation state must remain recoverable")
	}
	if entry, getErr := storage.Get(context.Background(), rotationStorageKey); getErr != nil || entry == nil {
		t.Fatalf("rotation state must be preserved: entry=%v err=%v", entry, getErr)
	}
}

func TestRotateRootRecoveryDropsStateWhenConfigIsGone(t *testing.T) {
	b, storage := newTestBackend(t, defaultMock())
	state := rotationState{OldTokenID: "vault-admin@pve!old", NewTokenID: "vault-admin@pve!new"}
	if err := putRotationState(context.Background(), storage, state); err != nil {
		t.Fatal(err)
	}
	if err := storage.Delete(context.Background(), "config"); err != nil {
		t.Fatal(err)
	}
	if err := b.walRollback(context.Background(), &logical.Request{Storage: storage}, walTypeRotation, state); err != nil {
		t.Fatalf("missing-config recovery failed: %v", err)
	}
	if entry, getErr := storage.Get(context.Background(), rotationStorageKey); getErr != nil || entry != nil {
		t.Fatalf("terminal rotation state was not dropped: entry=%v err=%v", entry, getErr)
	}
}
