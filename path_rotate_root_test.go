package proxmox

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
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
			return existsCalls == 1 || existsCalls == 2, nil
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
	if len(calls) != 4 || calls[0] != "confirm" || calls[1] != "confirm" || calls[2] != "delete" || calls[3] != "confirm" {
		t.Fatalf("deletion calls=%v, want confirm, confirm, delete, confirm", calls)
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
		mc.TokenExistsFn = func(context.Context, string, string) (bool, error) {
			existsCalls++
			return existsCalls == 1 || existsCalls == 2, nil
		}
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
	} else {
		var state rotationState
		if decodeErr := entry.DecodeJSON(&state); decodeErr != nil {
			t.Fatal(decodeErr)
		}
		if state.WALID == "" {
			t.Fatal("rotation state must persist the exact WAL ID")
		}
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
	walID, err := framework.PutWAL(context.Background(), storage, walTypeRotation, state)
	if err != nil {
		t.Fatal(err)
	}
	state.WALID = walID
	if stateErr := putRotationState(context.Background(), storage, state); stateErr != nil {
		t.Fatal(stateErr)
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

func TestRotateRootGuardedRecoverySelectsExactTokenWhenConfigNamesNeither(t *testing.T) {
	ctx := context.Background()
	var deleted string
	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		checks := 0
		mc.TokenExistsFn = func(context.Context, string, string) (bool, error) {
			checks++
			return checks == 1, nil
		}
		mc.DeleteTokenFn = func(_ context.Context, _, token string) error {
			deleted = token
			return nil
		}
	})
	if _, err := writeConfig(ctx, b, storage, map[string]interface{}{
		"address": "https://pve.example.com:8006", "token_id": "vault-admin@pve!third",
		"token_secret": "configured-secret", "tls_skip_verify": true,
	}); err != nil {
		t.Fatal(err)
	}
	state := rotationState{OldTokenID: "vault-admin@pve!old", NewTokenID: "vault-admin@pve!new"}
	walID, err := framework.PutWAL(ctx, storage, walTypeRotation, state)
	if err != nil {
		t.Fatal(err)
	}
	state.WALID = walID
	if stateErr := putRotationState(ctx, storage, state); stateErr != nil {
		t.Fatal(stateErr)
	}
	resp, err := b.recoverRotation(ctx, &logical.Request{Storage: storage}, "vault-admin@pve!third", state.NewTokenID)
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("guarded recovery failed: response=%v err=%v", resp, err)
	}
	if deleted != "new" {
		t.Fatalf("recovery deleted %q, want exact recorded new token", deleted)
	}
	if entry, err := framework.GetWAL(ctx, storage, walID); err != nil || entry != nil {
		t.Fatalf("recovery did not delete exact WAL: entry=%v err=%v", entry, err)
	}
}

func TestRotateRootRecoveryWithoutWALRefusesBeforeTokenMutation(t *testing.T) {
	calls := 0
	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		mc.TokenExistsFn = func(context.Context, string, string) (bool, error) {
			calls++
			return true, nil
		}
		mc.DeleteTokenFn = func(context.Context, string, string) error {
			calls++
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
	_, err := b.recoverRotation(context.Background(), &logical.Request{Storage: storage}, "vault-admin@pve!mytoken", state.NewTokenID)
	if err == nil || !strings.Contains(err.Error(), "no WAL ID") {
		t.Fatalf("legacy recovery should fail before mutation: %v", err)
	}
	if calls != 0 {
		t.Fatalf("legacy recovery mutated tokens through %d PVE calls", calls)
	}
}

func TestRotateRootRecoveryDeletesExactWALAndDoesNotPoisonNextRotation(t *testing.T) {
	ctx := context.Background()
	existsCalls := 0
	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		mc.TokenExistsFn = func(context.Context, string, string) (bool, error) {
			existsCalls++
			return existsCalls == 1, nil
		}
	})
	if _, err := writeConfig(ctx, b, storage, validConfigData()); err != nil {
		t.Fatal(err)
	}
	stateA := rotationState{OldTokenID: "vault-admin@pve!old-a", NewTokenID: "vault-admin@pve!new-a"}
	walA, err := framework.PutWAL(ctx, storage, walTypeRotation, stateA)
	if err != nil {
		t.Fatal(err)
	}
	stateA.WALID = walA
	if stateErr := putRotationState(ctx, storage, stateA); stateErr != nil {
		t.Fatal(stateErr)
	}
	if _, configErr := writeConfig(ctx, b, storage, map[string]interface{}{
		"address": "https://pve.example.com:8006", "token_id": stateA.NewTokenID,
		"token_secret": "replacement-secret", "tls_skip_verify": true,
	}); configErr != nil {
		t.Fatal(configErr)
	}
	resp, err := b.recoverRotation(ctx, &logical.Request{Storage: storage}, stateA.NewTokenID, stateA.OldTokenID)
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("recovery A failed: response=%v err=%v", resp, err)
	}
	if entry, walErr := framework.GetWAL(ctx, storage, walA); walErr != nil || entry != nil {
		t.Fatalf("WAL A remains after recovery: entry=%v err=%v", entry, walErr)
	}
	stateB := rotationState{OldTokenID: stateA.NewTokenID, NewTokenID: "vault-admin@pve!new-b"}
	walB, err := framework.PutWAL(ctx, storage, walTypeRotation, stateB)
	if err != nil {
		t.Fatal(err)
	}
	stateB.WALID = walB
	if err := putRotationState(ctx, storage, stateB); err != nil {
		t.Fatal(err)
	}
	if err := b.walRollback(ctx, &logical.Request{Storage: storage}, walTypeRotation, map[string]interface{}{
		"old_token_id": stateA.OldTokenID, "new_token_id": stateA.NewTokenID,
	}); err == nil {
		t.Fatal("stale WAL A must not clear or process rotation B state")
	}
	if entry, err := framework.GetWAL(ctx, storage, walB); err != nil || entry == nil {
		t.Fatalf("WAL B was poisoned by stale WAL A: entry=%v err=%v", entry, err)
	}
}

func TestRotateRootWALRollbackWithNewConfigDeletesOldToken(t *testing.T) {
	ctx := context.Background()
	var deletedUser, deletedToken string
	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		checks := 0
		mc.TokenExistsFn = func(context.Context, string, string) (bool, error) {
			checks++
			return checks == 1, nil
		}
		mc.DeleteTokenFn = func(_ context.Context, user, token string) error {
			deletedUser, deletedToken = user, token
			return nil
		}
	})
	if _, configErr := writeConfig(ctx, b, storage, map[string]interface{}{
		"address": "https://pve.example.com:8006", "token_id": "vault-admin@pve!new",
		"token_secret": "replacement-secret", "tls_skip_verify": true,
	}); configErr != nil {
		t.Fatal(configErr)
	}
	state := rotationState{OldTokenID: "vault-admin@pve!old", NewTokenID: "vault-admin@pve!new", WALID: "wal-a"}
	if stateErr := putRotationState(ctx, storage, state); stateErr != nil {
		t.Fatal(stateErr)
	}
	err := b.walRollback(ctx, &logical.Request{Storage: storage}, walTypeRotation, map[string]interface{}{
		"old_token_id": state.OldTokenID, "new_token_id": state.NewTokenID,
	})
	if err != nil {
		t.Fatalf("rollback failed: %v", err)
	}
	if deletedUser != "vault-admin@pve" || deletedToken != "old" {
		t.Fatalf("rollback deleted %q!%q, want vault-admin@pve!old", deletedUser, deletedToken)
	}
}

func TestReadRotationStateDistinguishesProgressAndRecovery(t *testing.T) {
	b, storage := newTestBackend(t, defaultMock())
	if _, err := writeConfig(context.Background(), b, storage, validConfigData()); err != nil {
		t.Fatal(err)
	}
	state := rotationState{OldTokenID: "vault-admin@pve!mytoken", NewTokenID: "vault-admin@pve!new", Phase: "in-progress", StartedAt: time.Now().Unix()}
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

func TestReadRotationStateUsesFactualPhases(t *testing.T) {
	ctx := context.Background()
	b, storage := newTestBackend(t, defaultMock())
	if _, err := writeConfig(ctx, b, storage, validConfigData()); err != nil {
		t.Fatal(err)
	}
	state := rotationState{OldTokenID: "vault-admin@pve!mytoken", NewTokenID: "vault-admin@pve!new", Phase: rotationPhaseConfigPersist, StartedAt: time.Now().Unix()}
	if err := putRotationState(ctx, storage, state); err != nil {
		t.Fatal(err)
	}
	resp, err := b.readRotationState(ctx, &logical.Request{Storage: storage}, nil)
	if err != nil || resp.Data["status"] != "recovery-required" {
		t.Fatalf("old configured token should require recovery: response=%v err=%v", resp, err)
	}
	if _, configErr := writeConfig(ctx, b, storage, map[string]interface{}{
		"address": "https://pve.example.com:8006", "token_id": state.NewTokenID,
		"token_secret": "replacement-secret", "tls_skip_verify": true,
	}); configErr != nil {
		t.Fatal(configErr)
	}
	resp, err = b.readRotationState(ctx, &logical.Request{Storage: storage}, nil)
	if err != nil || resp.Data["status"] != "in-progress" {
		t.Fatalf("config-persisted rotation should be in progress: response=%v err=%v", resp, err)
	}
	state.StartedAt = time.Now().Add(-rotationStaleAfter - time.Second).Unix()
	if stateErr := putRotationState(ctx, storage, state); stateErr != nil {
		t.Fatal(stateErr)
	}
	resp, err = b.readRotationState(ctx, &logical.Request{Storage: storage}, nil)
	if err != nil || resp.Data["status"] != "recovery-required" {
		t.Fatalf("stale rotation should require recovery: response=%v err=%v", resp, err)
	}
}

func TestRotateRootRetainsStateWhenAbsenceConfirmationFails(t *testing.T) {
	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		calls := 0
		mc.TokenExistsFn = func(context.Context, string, string) (bool, error) {
			calls++
			return calls <= 4, nil
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

func TestRotateRootRetainsStateWhenTokenStillExistsAfterDelete(t *testing.T) {
	var deletedUser, deletedToken string
	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		checks := 0
		mc.TokenExistsFn = func(context.Context, string, string) (bool, error) {
			checks++
			return true, nil
		}
		mc.DeleteTokenFn = func(_ context.Context, user, token string) error {
			deletedUser, deletedToken = user, token
			return nil
		}
	})
	if _, err := writeConfig(context.Background(), b, storage, validConfigData()); err != nil {
		t.Fatal(err)
	}
	_, err := b.HandleRequest(context.Background(), &logical.Request{Operation: logical.UpdateOperation, Path: "rotate-root", Storage: storage, Data: map[string]interface{}{
		"expected_token_id": "vault-admin@pve!mytoken", "confirm_exclusive": true,
	}})
	if err == nil || deletedUser != "vault-admin@pve" || deletedToken != "mytoken" {
		t.Fatalf("expected guarded failure with exact old token delete, err=%v deleted=%q!%q", err, deletedUser, deletedToken)
	}
	if entry, getErr := storage.Get(context.Background(), rotationStorageKey); getErr != nil || entry == nil {
		t.Fatalf("rotation state must remain after unconfirmed deletion: %v %v", entry, getErr)
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

func TestRotateRootRefusesAbsentConfiguredTokenAndRequiresRecovery(t *testing.T) {
	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		absent := false
		mc.TokenExistsResult = &absent
	})
	if _, err := writeConfig(context.Background(), b, storage, validConfigData()); err != nil {
		t.Fatal(err)
	}
	_, err := b.HandleRequest(context.Background(), &logical.Request{Operation: logical.UpdateOperation, Path: "rotate-root", Storage: storage, Data: map[string]interface{}{
		"expected_token_id": "vault-admin@pve!mytoken", "confirm_exclusive": true,
	}})
	if err == nil || !strings.Contains(err.Error(), "absent") || !strings.Contains(err.Error(), "fail-closed") {
		t.Fatalf("absent configured token should fail closed explicitly: %v", err)
	}
	entry, getErr := storage.Get(context.Background(), rotationStorageKey)
	if getErr != nil || entry == nil {
		t.Fatalf("recovery state must remain for explicit recovery: %v %v", entry, getErr)
	}
	resp, statusErr := b.readRotationState(context.Background(), &logical.Request{Storage: storage}, nil)
	if statusErr != nil || resp.Data["status"] != "recovery-required" {
		t.Fatalf("absent configured token status=%v err=%v, want recovery-required", resp, statusErr)
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

func TestRotateRootReplacementTokenListFailurePreservesOldConfigAndToken(t *testing.T) {
	ctx := context.Background()
	oldClient := &pveapi.MockClient{
		GetPermissionsResult: pveapi.PermissionTree{"/access/groups": {"User.Modify": 1, "Sys.Audit": 1}},
		CreateTokenResult:    "replacement-secret",
		TokenExistsFn: func(context.Context, string, string) (bool, error) {
			return true, nil
		},
	}
	deleteCalls := 0
	oldClient.DeleteTokenFn = func(context.Context, string, string) error {
		deleteCalls++
		return nil
	}
	replacementClient := &pveapi.MockClient{
		GetPermissionsResult: pveapi.PermissionTree{"/access/groups": {"User.Modify": 1, "Sys.Audit": 1}},
		TokenExistsFn: func(context.Context, string, string) (bool, error) {
			return false, errors.New("replacement token-list permission denied")
		},
	}
	b, storage := newTestBackend(t, nil)
	b.newClient = func(cfg *proxmoxConfig) (pveapi.Client, error) {
		if cfg.TokenSecret == "replacement-secret" {
			return replacementClient, nil
		}
		return oldClient, nil
	}
	if _, err := writeConfig(ctx, b, storage, validConfigData()); err != nil {
		t.Fatal(err)
	}
	_, err := b.HandleRequest(ctx, &logical.Request{Operation: logical.UpdateOperation, Path: "rotate-root", Storage: storage, Data: map[string]interface{}{
		"expected_token_id": "vault-admin@pve!mytoken", "confirm_exclusive": true,
	}})
	if err == nil || !strings.Contains(err.Error(), "replacement validation failed") {
		t.Fatalf("replacement token-list failure should abort validation: %v", err)
	}
	cfg, cfgErr := getConfig(ctx, storage)
	if cfgErr != nil || cfg == nil || cfg.TokenID != "vault-admin@pve!mytoken" || cfg.TokenSecret != "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" {
		t.Fatalf("old config changed after replacement validation failure: cfg=%+v err=%v", cfg, cfgErr)
	}
	if deleteCalls != 0 {
		t.Fatalf("old token was deleted before replacement validation completed: %d calls", deleteCalls)
	}
	stateEntry, stateErr := storage.Get(ctx, rotationStorageKey)
	if stateErr != nil || stateEntry == nil {
		t.Fatalf("rotation state was not retained: entry=%v err=%v", stateEntry, stateErr)
	}
	var state rotationState
	if decodeErr := stateEntry.DecodeJSON(&state); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if state.WALID == "" {
		t.Fatal("rotation state must retain its WAL ID")
	}
	walEntry, walErr := framework.GetWAL(ctx, storage, state.WALID)
	if walErr != nil || walEntry == nil {
		t.Fatalf("rotation WAL was not retained: entry=%v err=%v", walEntry, walErr)
	}
}

func TestRotateRootPostDeleteUserNotFoundConfirmsAbsence(t *testing.T) {
	checks := 0
	b, storage := newTestBackend(t, func(mc *pveapi.MockClient) {
		mc.TokenExistsFn = func(context.Context, string, string) (bool, error) {
			checks++
			if checks <= 2 {
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
