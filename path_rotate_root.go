package proxmox

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hazmei/vault-plugin-secrets-proxmox/internal/pveapi"
)

const (
	rotationStorageKey = "rotation"

	rotationPhaseProvisioning   = "provisioning"
	rotationPhaseValidationFail = "validation-failed"
	// rotationPhaseConfigPersist is retained for states written by versions
	// that persisted this phase before entering deleting-old. New rotations no
	// longer write it, but status and recovery remain upgrade-compatible.
	rotationPhaseConfigPersist = "config-persisted"
	rotationPhaseDeletingOld   = "deleting-old"
	// Intentionally matches this plugin's explicit WALRollbackMinAge of five
	// minutes. Changing either threshold requires reviewing the other.
	rotationStaleAfter = 5 * time.Minute
)

type rotationState struct {
	OldTokenID string `json:"old_token_id" mapstructure:"old_token_id"`
	NewTokenID string `json:"new_token_id" mapstructure:"new_token_id"`
	Phase      string `json:"phase" mapstructure:"phase"`
	WALID      string `json:"wal_id" mapstructure:"wal_id"`
	StartedAt  int64  `json:"started_at" mapstructure:"started_at"`
}

func pathRotateRoot(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "rotate-root",
		Fields: map[string]*framework.FieldSchema{
			"expected_token_id": {Type: framework.TypeString, Required: true, Description: "The complete token ID currently stored in config; prevents rotating a stale configuration."},
			"confirm_exclusive": {Type: framework.TypeBool, Required: true, Description: "Acknowledge that this mount exclusively owns the provisioner token and that shared tokens are unsupported."},
			"recovery_token_id": {Type: framework.TypeString, Required: false, Description: "During guarded recovery, the exact old_token_id or new_token_id from the pending rotation status; never a secret."},
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
		ExistenceCheck:  b.rotationExistenceCheck,
		HelpSynopsis:    "Rotate the dedicated Proxmox provisioner token.",
		HelpDescription: "Rotates the exclusive provisioner API token. The response and status expose token IDs only; token secrets remain in seal-wrapped config. If status reports recovery-required, automatic WAL rollback should be allowed to retry first. Guarded recovery requires expected_token_id, confirm_exclusive=true, and an exact recovery_token_id copied from the pending status; it refuses active or unrecorded IDs and never force-clears state.",
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
	cfg, cfgErr := getConfig(ctx, req.Storage)
	if cfgErr != nil {
		return nil, fmt.Errorf("proxmox: read config for rotation status: %w", cfgErr)
	}
	status := rotationStatus(state, cfg)
	return &logical.Response{Data: map[string]interface{}{
		"status": status, "old_token_id": state.OldTokenID, "new_token_id": state.NewTokenID,
	}}, nil
}

func rotationStatus(state rotationState, cfg *proxmoxConfig) string {
	if state.Phase == rotationPhaseValidationFail {
		return "recovery-required"
	}
	if cfg == nil {
		return "recovery-required"
	}
	if state.StartedAt == 0 || time.Since(time.Unix(state.StartedAt, 0)) > rotationStaleAfter {
		return "recovery-required"
	}
	if cfg.TokenID == state.OldTokenID && (state.Phase == rotationPhaseProvisioning || state.Phase == "in-progress") {
		return "in-progress"
	}
	if cfg.TokenID == state.NewTokenID && (state.Phase == rotationPhaseConfigPersist || state.Phase == rotationPhaseDeletingOld) {
		return "in-progress"
	}
	return "recovery-required"
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
	if recoveryToken, ok := d.GetOk("recovery_token_id"); ok && recoveryToken.(string) != "" {
		return b.recoverRotation(ctx, req, d.Get("expected_token_id").(string), recoveryToken.(string))
	}

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
	rotationTokenID := "vault-rotation-" + suffix
	newToken := oldUser + "!" + rotationTokenID
	state := rotationState{OldTokenID: cfg.TokenID, NewTokenID: newToken, Phase: rotationPhaseProvisioning, StartedAt: time.Now().Unix()}
	walID, err := framework.PutWAL(ctx, req.Storage, walTypeRotation, state)
	if err != nil {
		return nil, fmt.Errorf("proxmox: rotate-root: write recovery WAL: %w", err)
	}
	state.WALID = walID
	if stateErr := putRotationState(ctx, req.Storage, state); stateErr != nil {
		return nil, fmt.Errorf("proxmox: rotate-root: write rotation state (WAL %s retained): %w", walID, stateErr)
	}

	oldClient, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if exists, existsErr := oldClient.TokenExists(ctx, oldUser, oldToken); existsErr != nil {
		state.Phase = rotationPhaseValidationFail
		if stateErr := putRotationState(ctx, req.Storage, state); stateErr != nil {
			return nil, fmt.Errorf("proxmox: rotate-root: mark current-token validation failure: %w (original: %v)", stateErr, existsErr)
		}
		return nil, fmt.Errorf("proxmox: rotate-root: validate current token before replacement: %w", existsErr)
	} else if !exists {
		state.Phase = rotationPhaseValidationFail
		if stateErr := putRotationState(ctx, req.Storage, state); stateErr != nil {
			return nil, fmt.Errorf("proxmox: rotate-root: mark current-token validation failure: %w", stateErr)
		}
		return nil, fmt.Errorf("proxmox: rotate-root: current configured token %q is absent; rotation refused fail-closed; restore the token or use guarded recovery", oldToken)
	}
	secret, err := oldClient.CreateToken(ctx, oldUser, rotationTokenID)
	if err != nil {
		return nil, fmt.Errorf("proxmox: rotate-root: create replacement token: %w", err)
	}

	newCfg := *cfg
	newCfg.TokenID, newCfg.TokenSecret = newToken, secret
	replacement, err := b.newClient(&newCfg)
	if err != nil {
		return nil, fmt.Errorf("proxmox: rotate-root: build replacement client: %w", err)
	}
	if validationErr := validateReplacement(ctx, replacement, req.Storage, cfg.TokenID); validationErr != nil {
		state.Phase = rotationPhaseValidationFail
		if stateErr := putRotationState(ctx, req.Storage, state); stateErr != nil {
			return nil, fmt.Errorf("proxmox: rotate-root: mark validation failure: %w (original: %v)", stateErr, validationErr)
		}
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
	state.Phase = rotationPhaseDeletingOld
	if err := putRotationState(ctx, req.Storage, state); err != nil {
		return nil, fmt.Errorf("proxmox: rotate-root: mark deletion phase: %w", err)
	}
	if err := replacement.DeleteToken(ctx, oldUser, oldToken); err != nil && !errors.Is(err, pveapi.ErrTokenNotFound) {
		return nil, fmt.Errorf("proxmox: rotate-root: delete old token: %w", err)
	}
	if exists, err := replacement.TokenExists(ctx, oldUser, oldToken); err != nil && !errors.Is(err, pveapi.ErrUserNotFound) {
		return nil, fmt.Errorf("proxmox: rotate-root: confirm old token deletion: %w", err)
	} else if exists {
		return nil, fmt.Errorf("proxmox: rotate-root: old token deletion could not be confirmed")
	}
	if err := framework.DeleteWAL(ctx, req.Storage, walID); err != nil {
		return nil, fmt.Errorf("proxmox: rotate-root: clear recovery WAL: %w", err)
	}
	if err := req.Storage.Delete(ctx, rotationStorageKey); err != nil {
		return nil, fmt.Errorf("proxmox: rotate-root: clear rotation state: %w", err)
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

func validateReplacement(ctx context.Context, client pveapi.Client, storage logical.Storage, oldTokenID string) error {
	if _, err := client.GetVersion(ctx); err != nil {
		return err
	}
	oldUser, oldToken, err := splitTokenID(oldTokenID)
	if err != nil {
		return fmt.Errorf("validate current token for replacement: %w", err)
	}
	// Second existence check, deliberately on the replacement client: rotateRoot
	// already confirmed the token is live via oldClient before CreateToken. This
	// one proves the replacement can list tokens, a distinct PVE permission that
	// the post-delete confirmation depends on, and must run before config
	// persistence so a replacement that cannot list fails closed.
	exists, err := client.TokenExists(ctx, oldUser, oldToken)
	if err != nil {
		return fmt.Errorf("validate replacement token-list capability: %w", err)
	}
	if !exists {
		return fmt.Errorf("current configured token %q is absent during replacement validation", oldToken)
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

func (b *backend) recoverRotation(ctx context.Context, req *logical.Request, expected, recoveryToken string) (*logical.Response, error) {
	stateEntry, err := req.Storage.Get(ctx, rotationStorageKey)
	if err != nil {
		return nil, fmt.Errorf("proxmox: read rotation state: %w", err)
	}
	if stateEntry == nil {
		return logical.ErrorResponse("rotate-root recovery found no pending rotation"), nil
	}
	var state rotationState
	if decodeErr := stateEntry.DecodeJSON(&state); decodeErr != nil {
		return nil, fmt.Errorf("proxmox: decode rotation state: %w", decodeErr)
	}
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil || cfg == nil {
		if err != nil {
			return nil, err
		}
		return logical.ErrorResponse("rotate-root recovery requires an existing configuration"), nil
	}
	if expected != cfg.TokenID {
		return logical.ErrorResponse("rotate-root recovery rejected: expected_token_id does not match current token ID"), nil
	}
	if recoveryToken != state.OldTokenID && recoveryToken != state.NewTokenID {
		return logical.ErrorResponse("rotate-root recovery rejected: recovery_token_id must equal old_token_id or new_token_id"), nil
	}
	if recoveryToken == cfg.TokenID {
		return logical.ErrorResponse("rotate-root recovery rejected: recovery_token_id is the active configured token"), nil
	}
	if state.WALID == "" {
		return nil, fmt.Errorf("proxmox: rotation recovery state has no WAL ID; refusing to mutate tokens; automatic WAL rollback must resolve this legacy state")
	}
	user, token, err := splitTokenID(recoveryToken)
	if err != nil {
		return logical.ErrorResponse("rotate-root recovery: %s", err), nil
	}
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	exists, err := client.TokenExists(ctx, user, token)
	if err != nil && !errors.Is(err, pveapi.ErrUserNotFound) {
		return nil, fmt.Errorf("proxmox: verify recovery token: %w", err)
	}
	if err == nil && exists {
		if deleteErr := client.DeleteToken(ctx, user, token); deleteErr != nil && !errors.Is(deleteErr, pveapi.ErrTokenNotFound) {
			return nil, deleteErr
		}
		exists, err = client.TokenExists(ctx, user, token)
		if err != nil && !errors.Is(err, pveapi.ErrUserNotFound) {
			return nil, fmt.Errorf("proxmox: confirm recovery token deletion: %w", err)
		}
		if err == nil && exists {
			return nil, fmt.Errorf("proxmox: recovery token deletion could not be confirmed")
		}
	}
	if err := framework.DeleteWAL(ctx, req.Storage, state.WALID); err != nil {
		return nil, fmt.Errorf("proxmox: delete rotation recovery WAL %q: %w", state.WALID, err)
	}
	if err := req.Storage.Delete(ctx, rotationStorageKey); err != nil {
		return nil, err
	}
	return &logical.Response{Data: map[string]interface{}{"status": "recovered", "token_id": recoveryToken}}, nil
}
