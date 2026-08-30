package proxmox

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hazmei/vault-plugin-secrets-proxmox/internal/pveapi"
)

const rotationStorageKey = "rotation"

type rotationState struct {
	OldTokenID string `json:"old_token_id" mapstructure:"old_token_id"`
	NewTokenID string `json:"new_token_id" mapstructure:"new_token_id"`
}

func pathRotateRoot(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "rotate-root",
		Fields: map[string]*framework.FieldSchema{
			"expected_token_id": {Type: framework.TypeString, Required: true},
			"confirm_exclusive": {Type: framework.TypeBool, Required: true},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{Callback: b.readRotationState},
			logical.CreateOperation: &framework.PathOperation{
				Callback:                    b.rotateRoot,
				ForwardPerformanceStandby:   true,
				ForwardPerformanceSecondary: true,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback:                    b.rotateRoot,
				ForwardPerformanceStandby:   true,
				ForwardPerformanceSecondary: true,
			},
		},
		ExistenceCheck: b.rotationExistenceCheck,
		HelpSynopsis:   "Rotate the dedicated Proxmox provisioner token.",
	}
}

func (b *backend) rotationExistenceCheck(ctx context.Context, req *logical.Request, _ *framework.FieldData) (bool, error) {
	entry, err := req.Storage.Get(ctx, rotationStorageKey)
	return entry != nil, err
}

func (b *backend) readRotationState(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	entry, err := req.Storage.Get(ctx, rotationStorageKey)
	if err != nil {
		return nil, fmt.Errorf("proxmox: read rotation state: %w", err)
	}
	if entry == nil {
		return nil, nil
	}
	var state rotationState
	if err := entry.DecodeJSON(&state); err != nil {
		return nil, fmt.Errorf("proxmox: decode rotation state: %w", err)
	}
	return &logical.Response{Data: map[string]interface{}{
		"status": "recovery-required", "old_token_id": state.OldTokenID, "new_token_id": state.NewTokenID,
	}}, nil
}

func splitTokenID(tokenID string) (string, string, error) {
	idx := strings.LastIndex(tokenID, "!")
	if idx <= 0 || idx == len(tokenID)-1 {
		return "", "", fmt.Errorf("invalid token_id: expected <user>@<realm>!<tokenid>")
	}
	return tokenID[:idx], tokenID[idx+1:], nil
}

func (b *backend) rotateRoot(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if !d.Get("confirm_exclusive").(bool) {
		return logical.ErrorResponse("rotate-root requires confirm_exclusive=true; shared provisioner tokens are unsupported"), nil
	}
	b.rotationLock.Lock()
	defer b.rotationLock.Unlock()

	cfg, err := getConfig(ctx, req.Storage)
	if err != nil || cfg == nil {
		if err == nil {
			return logical.ErrorResponse("rotate-root requires an existing configuration"), nil
		}
		return nil, fmt.Errorf("proxmox: rotate-root: read config: %w", err)
	}
	expected := d.Get("expected_token_id").(string)
	if expected != cfg.TokenID {
		return logical.ErrorResponse("rotate-root rejected: expected_token_id does not match the current token ID"), nil
	}
	if entry, readErr := req.Storage.Get(ctx, rotationStorageKey); readErr != nil {
		return nil, fmt.Errorf("proxmox: rotate-root: read rotation state: %w", readErr)
	} else if entry != nil {
		return logical.ErrorResponse("rotate-root rejected: another rotation is active or requires recovery"), nil
	}
	oldUser, oldToken, err := splitTokenID(cfg.TokenID)
	if err != nil {
		return logical.ErrorResponse("rotate-root: %s", err), nil
	}
	suffix, err := randomSuffix()
	if err != nil {
		return nil, fmt.Errorf("proxmox: rotate-root: generate token ID: %w", err)
	}
	newToken := oldUser + "!vault-rotation-" + suffix
	state := rotationState{OldTokenID: cfg.TokenID, NewTokenID: newToken}
	walID, err := framework.PutWAL(ctx, req.Storage, walTypeRotation, state)
	if err != nil {
		return nil, fmt.Errorf("proxmox: rotate-root: write recovery WAL: %w", err)
	}
	if stateErr := putRotationState(ctx, req.Storage, state); stateErr != nil {
		return nil, fmt.Errorf("proxmox: rotate-root: write rotation state (WAL %s retained): %w", walID, stateErr)
	}

	oldClient, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	secret, err := oldClient.CreateToken(ctx, oldUser, "vault-rotation-"+suffix)
	if err != nil {
		return nil, fmt.Errorf("proxmox: rotate-root: create replacement token: %w", err)
	}

	newCfg := *cfg
	newCfg.TokenID, newCfg.TokenSecret = newToken, secret
	replacement, err := b.newClient(&newCfg)
	if err != nil {
		return nil, fmt.Errorf("proxmox: rotate-root: build replacement client: %w", err)
	}
	if validationErr := validateReplacement(ctx, replacement, req.Storage); validationErr != nil {
		return nil, fmt.Errorf("proxmox: rotate-root: replacement validation failed: %w", validationErr)
	}
	entry, err := logical.StorageEntryJSON("config", &newCfg)
	if err != nil {
		return nil, fmt.Errorf("proxmox: rotate-root: encode config: %w", err)
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, fmt.Errorf("proxmox: rotate-root: persist replacement config: %w", err)
	}
	b.invalidate(ctx, "config")

	if err := replacement.DeleteToken(ctx, oldUser, oldToken); err != nil && !errors.Is(err, pveapi.ErrTokenNotFound) {
		return nil, fmt.Errorf("proxmox: rotate-root: delete old token: %w", err)
	}
	if exists, err := replacement.TokenExists(ctx, oldUser, oldToken); err != nil {
		return nil, fmt.Errorf("proxmox: rotate-root: confirm old token deletion: %w", err)
	} else if exists {
		return nil, fmt.Errorf("proxmox: rotate-root: old token deletion could not be confirmed")
	}
	if err := req.Storage.Delete(ctx, rotationStorageKey); err != nil {
		return nil, fmt.Errorf("proxmox: rotate-root: clear rotation state: %w", err)
	}
	if err := framework.DeleteWAL(ctx, req.Storage, walID); err != nil {
		return nil, fmt.Errorf("proxmox: rotate-root: clear recovery WAL: %w", err)
	}
	return &logical.Response{Data: map[string]interface{}{"token_id": newToken, "status": "rotated"}}, nil
}

func putRotationState(ctx context.Context, storage logical.Storage, state rotationState) error {
	entry, err := logical.StorageEntryJSON(rotationStorageKey, state)
	if err != nil {
		return err
	}
	return storage.Put(ctx, entry)
}

func validateReplacement(ctx context.Context, client pveapi.Client, storage logical.Storage) error {
	if _, err := client.GetVersion(ctx); err != nil {
		return err
	}
	tree, err := client.GetPermissions(ctx)
	if err != nil {
		return err
	}
	for _, required := range []struct{ privilege, path string }{
		{"User.Modify", "/access/groups"}, {"Sys.Audit", "/access/groups"},
	} {
		if !tree.HasPrivilege(required.path, required.privilege) {
			return fmt.Errorf("replacement token lacks %s at %s", required.privilege, required.path)
		}
	}
	roles, err := storage.List(ctx, "roles/")
	if err != nil {
		return fmt.Errorf("list roles for replacement validation: %w", err)
	}
	for _, name := range roles {
		role, roleErr := getRole(ctx, storage, name)
		if roleErr != nil {
			return roleErr
		}
		if role != nil && !tree.HasPrivilege("/access/realm/"+role.Realm, "Realm.AllocateUser") {
			return fmt.Errorf("replacement token lacks Realm.AllocateUser at /access/realm/%s for role %q", role.Realm, name)
		}
	}
	return nil
}
