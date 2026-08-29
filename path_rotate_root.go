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
			err = fmt.Errorf("no configuration found")
		}
		return nil, fmt.Errorf("proxmox: rotate-root: read config: %w", err)
	}
	expected := d.Get("expected_token_id").(string)
	if expected != cfg.TokenID {
		return logical.ErrorResponse("rotate-root rejected: expected_token_id does not match the current token ID"), nil
	}
	if entry, err := req.Storage.Get(ctx, rotationStorageKey); err != nil {
		return nil, fmt.Errorf("proxmox: rotate-root: read rotation state: %w", err)
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
	newToken := oldUser + "!" + suffix
	state := rotationState{OldTokenID: cfg.TokenID, NewTokenID: newToken}
	walID, err := framework.PutWAL(ctx, req.Storage, walTypeRotation, state)
	if err != nil {
		return nil, fmt.Errorf("proxmox: rotate-root: write recovery WAL: %w", err)
	}
	if err := putRotationState(ctx, req.Storage, state); err != nil {
		return nil, fmt.Errorf("proxmox: rotate-root: write rotation state (WAL %s retained): %w", walID, err)
	}

	oldClient, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	secret, err := oldClient.CreateToken(ctx, oldUser, newToken[strings.LastIndex(newToken, "!")+1:])
	if err != nil {
		return nil, fmt.Errorf("proxmox: rotate-root: create replacement token: %w", err)
	}

	newCfg := *cfg
	newCfg.TokenID, newCfg.TokenSecret = newToken, secret
	replacement, err := b.newClient(&newCfg)
	if err != nil {
		return nil, fmt.Errorf("proxmox: rotate-root: build replacement client: %w", err)
	}
	if err := validateReplacement(ctx, replacement); err != nil {
		return nil, fmt.Errorf("proxmox: rotate-root: replacement validation failed: %w", err)
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
	if err := replacement.DeleteToken(ctx, oldUser, oldToken); !errors.Is(err, pveapi.ErrTokenNotFound) {
		if err == nil {
			return nil, fmt.Errorf("proxmox: rotate-root: old token deletion could not be confirmed")
		}
		return nil, fmt.Errorf("proxmox: rotate-root: confirm old token deletion: %w", err)
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

func validateReplacement(ctx context.Context, client pveapi.Client) error {
	if _, err := client.GetVersion(ctx); err != nil {
		return err
	}
	tree, err := client.GetPermissions(ctx)
	if err != nil {
		return err
	}
	if !tree.HasPrivilege("/access/groups", "User.Modify") || !tree.HasPrivilege("/access/groups", "Sys.Audit") {
		return fmt.Errorf("replacement token lacks required permissions")
	}
	return nil
}
