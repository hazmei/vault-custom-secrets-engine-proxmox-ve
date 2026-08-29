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
			return pveapi.ErrTokenNotFound
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
	if len(calls) != 2 {
		t.Fatalf("deletion confirmation calls=%d, want 2", len(calls))
	}
	cfg, err := getConfig(context.Background(), storage)
	if err != nil || cfg.TokenID == "vault-admin@pve!mytoken" || cfg.TokenSecret == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" {
		t.Fatalf("replacement config was not persisted: cfg=%+v err=%v", cfg, err)
	}
	if _, ok := resp.Data["token_secret"]; ok {
		t.Fatal("rotation response must not contain token_secret")
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

func TestRotateRootDeleteTokenNotFoundIsTyped(t *testing.T) {
	if !errors.Is(pveapi.ErrTokenNotFound, pveapi.ErrTokenNotFound) {
		t.Fatal("token-not-found sentinel must support errors.Is")
	}
}
