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
	existsCalls := 0
	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		mc.GetPermissionsResult = pveapi.PermissionTree{"/access/groups": {"User.Modify": 1, "Sys.Audit": 1}}
		mc.DeleteTokenFn = func(_ context.Context, _, _ string) error {
			calls = append(calls, "delete")
			return nil
		}
		mc.TokenExistsFn = func(_ context.Context, _, _ string) (bool, error) {
			calls = append(calls, "confirm")
			existsCalls++
			return existsCalls == 1, nil
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
	if len(calls) != 3 || calls[0] != "confirm" || calls[1] != "delete" || calls[2] != "confirm" {
		t.Fatalf("deletion calls=%v, want confirm, delete, confirm", calls)
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
	existsCalls := 0
	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		mc.DeleteTokenFn = func(context.Context, string, string) error { return pveapi.ErrTokenNotFound }
		mc.TokenExistsFn = func(context.Context, string, string) (bool, error) { existsCalls++; return existsCalls == 1, nil }
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
	existsCalls := 0
	mc := &pveapi.MockClient{
		DeleteTokenFn: func(_ context.Context, _, token string) error { deleted = token; return nil },
		TokenExistsFn: func(context.Context, string, string) (bool, error) { existsCalls++; return existsCalls == 1, nil },
	}
	b, storage := newTestBackend(t, nil)
	b.newClient = func(_ *proxmoxConfig) (pveapi.Client, error) { return mc, nil }
	if _, err := writeConfig(context.Background(), b, storage, validConfigData()); err != nil {
		t.Fatal(err)
	}
	data := map[string]interface{}{"old_token_id": "vault-admin@pve!mytoken", "new_token_id": "vault-admin@pve!replacement"}
	if err := putRotationState(context.Background(), storage, rotationState{OldTokenID: data["old_token_id"].(string), NewTokenID: data["new_token_id"].(string)}); err != nil {
		t.Fatal(err)
	}
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
	if putErr := putRotationState(context.Background(), storage, state); putErr != nil {
		t.Fatal(putErr)
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
	if putErr := putRotationState(context.Background(), storage, state); putErr != nil {
		t.Fatal(putErr)
	}
	if err := storage.Delete(context.Background(), "config"); err != nil {
		t.Fatal(err)
	}
	if err := b.walRollback(context.Background(), &logical.Request{Storage: storage}, walTypeRotation, state); err == nil {
		t.Fatal("missing-config recovery must preserve state")
	}
	if entry, getErr := storage.Get(context.Background(), rotationStorageKey); getErr != nil || entry == nil {
		t.Fatalf("rotation state must be preserved: entry=%v err=%v", entry, getErr)
	}
}

func TestRotateRootRecoveryOperationDeletesOnlyVerifiedStateToken(t *testing.T) {
	var calls []string
	seen := 0
	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		mc.TokenExistsFn = func(_ context.Context, user, token string) (bool, error) {
			calls = append(calls, "exists:"+user+"!"+token)
			seen++
			return seen == 1, nil
		}
		mc.DeleteTokenFn = func(_ context.Context, user, token string) error {
			calls = append(calls, "delete:"+user+"!"+token)
			return nil
		}
	})
	if _, err := writeConfig(context.Background(), b, storage, validConfigData()); err != nil {
		t.Fatal(err)
	}
	state := rotationState{OldTokenID: "vault-admin@pve!old", NewTokenID: "vault-admin@pve!new"}
	if err := putRotationState(context.Background(), storage, state); err != nil {
		t.Fatal(err)
	}
	resp, err := b.HandleRequest(context.Background(), &logical.Request{Operation: logical.UpdateOperation, Path: "rotate-root", Storage: storage, Data: map[string]interface{}{
		"expected_token_id": "vault-admin@pve!wrong", "confirm_exclusive": true, "recovery_token_id": state.NewTokenID,
	}})
	if err != nil || resp == nil || !resp.IsError() {
		t.Fatal("recovery must refuse when expected token does not match config")
	}
	if len(calls) != 0 {
		t.Fatalf("refusal must not call PVE: %v", calls)
	}
	resp, err = b.HandleRequest(context.Background(), &logical.Request{Operation: logical.UpdateOperation, Path: "rotate-root", Storage: storage, Data: map[string]interface{}{
		"expected_token_id": "vault-admin@pve!mytoken", "confirm_exclusive": true, "recovery_token_id": state.NewTokenID,
	}})
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("verified recovery failed: response=%v err=%v", resp, err)
	}
	if len(calls) != 3 || calls[0] != "exists:vault-admin@pve!new" || calls[1] != "delete:vault-admin@pve!new" || calls[2] != "exists:vault-admin@pve!new" {
		t.Fatalf("recovery calls=%v", calls)
	}
}

func TestReadRotationStateDistinguishesProgressAndRecovery(t *testing.T) {
	b, storage := newTestBackend(t, defaultMock())
	if _, err := writeConfig(context.Background(), b, storage, validConfigData()); err != nil {
		t.Fatal(err)
	}
	state := rotationState{OldTokenID: "vault-admin@pve!mytoken", NewTokenID: "vault-admin@pve!new", Phase: "in-progress"}
	if err := putRotationState(context.Background(), storage, state); err != nil {
		t.Fatal(err)
	}
	resp, err := b.readRotationState(context.Background(), &logical.Request{Storage: storage}, nil)
	if err != nil || resp.Data["status"] != "in-progress" {
		t.Fatalf("status=%v err=%v", resp, err)
	}
	state.Phase = "recovery-required"
	if putErr := putRotationState(context.Background(), storage, state); putErr != nil {
		t.Fatal(putErr)
	}
	resp, err = b.readRotationState(context.Background(), &logical.Request{Storage: storage}, nil)
	if err != nil || resp.Data["status"] != "recovery-required" {
		t.Fatalf("status=%v err=%v", resp, err)
	}
}

func TestRotateRootRetainsStateWhenAbsenceConfirmationFails(t *testing.T) {
	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		calls := 0
		mc.TokenExistsFn = func(context.Context, string, string) (bool, error) {
			calls++
			return calls == 1 || calls == 2, nil
		}
	})
	if _, err := writeConfig(context.Background(), b, storage, validConfigData()); err != nil {
		t.Fatal(err)
	}
	resp, err := b.HandleRequest(context.Background(), &logical.Request{Operation: logical.UpdateOperation, Path: "rotate-root", Storage: storage, Data: map[string]interface{}{
		"expected_token_id": "vault-admin@pve!mytoken", "confirm_exclusive": true,
	}})
	if err == nil || resp != nil {
		t.Fatalf("confirmation failure must return error only: response=%v err=%v", resp, err)
	}
	if entry, getErr := storage.Get(context.Background(), rotationStorageKey); getErr != nil || entry == nil {
		t.Fatalf("state lost after confirmation failure: %v %v", entry, getErr)
	}
}

func TestRotateRootReplacementValidationFailurePrecedesConfigWrite(t *testing.T) {
	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		mc.TokenExistsFn = func(context.Context, string, string) (bool, error) { return false, nil }
	})
	if _, err := writeConfig(context.Background(), b, storage, validConfigData()); err != nil {
		t.Fatal(err)
	}
	_, err := b.HandleRequest(context.Background(), &logical.Request{Operation: logical.UpdateOperation, Path: "rotate-root", Storage: storage, Data: map[string]interface{}{
		"expected_token_id": "vault-admin@pve!mytoken", "confirm_exclusive": true,
	}})
	if err == nil {
		t.Fatal("replacement validation failure must abort rotation")
	}
	cfg, cfgErr := getConfig(context.Background(), storage)
	if cfgErr != nil || cfg.TokenID != "vault-admin@pve!mytoken" {
		t.Fatalf("config changed after validation failure: %+v %v", cfg, cfgErr)
	}
}

func TestRotateRootTokenListErrorRetainsRecoveryState(t *testing.T) {
	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		mc.TokenExistsFn = func(context.Context, string, string) (bool, error) {
			return false, errors.New("token list unavailable")
		}
	})
	if _, err := writeConfig(context.Background(), b, storage, validConfigData()); err != nil {
		t.Fatal(err)
	}
	_, err := b.HandleRequest(context.Background(), &logical.Request{Operation: logical.UpdateOperation, Path: "rotate-root", Storage: storage, Data: map[string]interface{}{
		"expected_token_id": "vault-admin@pve!mytoken", "confirm_exclusive": true,
	}})
	if err == nil {
		t.Fatal("token-list error must abort rotation")
	}
	if entry, getErr := storage.Get(context.Background(), rotationStorageKey); getErr != nil || entry == nil {
		t.Fatalf("recovery state lost: %v %v", entry, getErr)
	}
}

func TestRotateRootPostDeleteUserNotFoundConfirmsAbsence(t *testing.T) {
	checks := 0
	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		mc.TokenExistsFn = func(context.Context, string, string) (bool, error) {
			checks++
			if checks == 1 {
				return true, nil
			}
			return false, pveapi.ErrUserNotFound
		}
		mc.DeleteTokenFn = func(context.Context, string, string) error { return nil }
	})
	if _, err := writeConfig(context.Background(), b, storage, validConfigData()); err != nil {
		t.Fatal(err)
	}
	resp, err := b.HandleRequest(context.Background(), &logical.Request{Operation: logical.UpdateOperation, Path: "rotate-root", Storage: storage, Data: map[string]interface{}{
		"expected_token_id": "vault-admin@pve!mytoken", "confirm_exclusive": true,
	}})
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("ErrUserNotFound confirmation should succeed: %v %v", resp, err)
	}
}

func TestRotateRootMalformedWALCannotClearUnrelatedState(t *testing.T) {
	b, storage := newTestBackend(t, defaultMock())
	if _, err := writeConfig(context.Background(), b, storage, validConfigData()); err != nil {
		t.Fatal(err)
	}
	state := rotationState{OldTokenID: "vault-admin@pve!old", NewTokenID: "vault-admin@pve!new"}
	if err := putRotationState(context.Background(), storage, state); err != nil {
		t.Fatal(err)
	}
	err := b.walRollback(context.Background(), &logical.Request{Storage: storage}, walTypeRotation, map[string]interface{}{
		"old_token_id": "vault-admin@pve!other", "new_token_id": "vault-admin@pve!new",
	})
	if err == nil {
		t.Fatal("mismatched malformed WAL must be retained")
	}
	if entry, getErr := storage.Get(context.Background(), rotationStorageKey); getErr != nil || entry == nil {
		t.Fatalf("shared state was cleared: %v %v", entry, getErr)
	}
}

func TestRotateRootUndecodableWALCannotClearState(t *testing.T) {
	b, storage := newTestBackend(t, defaultMock())
	if err := putRotationState(context.Background(), storage, rotationState{OldTokenID: "vault-admin@pve!old", NewTokenID: "vault-admin@pve!new"}); err != nil {
		t.Fatal(err)
	}
	if err := b.walRollback(context.Background(), &logical.Request{Storage: storage}, walTypeRotation, make(chan int)); err == nil {
		t.Fatal("undecodable WAL must be retained")
	}
	if entry, getErr := storage.Get(context.Background(), rotationStorageKey); getErr != nil || entry == nil {
		t.Fatal("undecodable WAL cleared shared state")
	}
}
