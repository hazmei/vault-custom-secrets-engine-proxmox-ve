// WAL-based orphan recovery for partially-created Proxmox VE users.
//
// # Accepted Risk
//
// The engine's admin token holds User.Modify on /access/groups (parent path,
// propagating). A compromised admin token can therefore: (1) add itself to any
// existing privileged group via the normal workflow (creates a new synthetic
// user in a group that a cluster admin has bound to a high-privilege role —
// looks like routine issuance activity, harder to spot than the self-modification
// route), or (2) modify the admin user's own group membership via
// PUT /access/users/<admin_user>. Both routes reach the same privilege ceiling
// (any role bound to any group on the cluster). This is the accepted design
// trade-off for a dynamic-secrets engine that delegates role assignment through
// operator-pre-created groups; per-group scoping is not achievable for renewal
// and revocation because PVE checks User.Modify at the parent /access/groups
// path for those operations. The full threat model is documented in
// docs/ARCHITECTURE.md § Security Considerations.
//
// # WAL Nonce Ownership
//
// walUser carries a per-attempt random nonce written into both the WAL entry
// and the PVE user's comment field at creation time. walRollbackUser verifies
// the nonce before deleting: a comment mismatch (or absent comment) means the
// userid belongs to a foreign/pre-existing user and must NOT be deleted. This
// closes the stale-WAL foreign-user-deletion class: a WAL entry that names a
// colliding userid we did NOT create cannot trigger deletion of that foreign user.
package proxmox

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hazmei/vault-plugin-secrets-proxmox/internal/pveapi"
	"github.com/mitchellh/mapstructure"
)

const (
	// walTypeUser is the WAL kind written when a synthetic PVE user has been
	// created but the overall credential issuance has not yet completed.
	// walRollback uses this kind to identify user-cleanup entries.
	walTypeUser     = "user"
	walTypeRotation = "root-rotation"

	// walCommentPrefix is prepended to the random nonce written into both the
	// WAL entry (walUser.Nonce) and the PVE user's comment field at creation
	// time. The prefix makes the marker self-documenting when operators browse
	// the Proxmox VE UI or API — they see "vault-wal:<random>" rather than a
	// bare random string. Both the WAL nonce and the PVE comment carry the
	// full prefixed value so walRollbackUser's ownership comparison remains a
	// simple string equality check with no stripping required.
	//
	// WARNING: Operators must not edit the comment field on vault-* synthetic
	// users in the PVE UI. The engine uses this field as an ownership marker
	// for WAL-based crash recovery. Editing or clearing the comment causes
	// walRollbackUser to treat the user as a foreign/pre-existing account and
	// skip automatic cleanup — the user will leak as a dead account until
	// manually removed (the PVE expire backstop still prevents authentication).
	walCommentPrefix = "vault-wal:"
)

// walUser is the payload stored in a WAL entry of kind walTypeUser.
// It contains enough information to delete the orphaned PVE user if the
// issuance operation fails after CreateUser but before the lease is returned.
//
// JSON tags make the struct round-trip cleanly through framework.PutWAL
// (which JSON-encodes the Data field). mapstructure tags allow decoding from
// the map[string]interface{} that framework.GetWAL returns for WALEntry.Data.
type walUser struct {
	// UserID is the fully-qualified Proxmox VE userid, e.g.
	// "vault-myrole-a3b7x2kp@pve". Stored at WAL-write time so the rollback
	// callback can issue the DELETE even without loading the role config.
	UserID string `json:"user_id" mapstructure:"user_id"`

	// Nonce is a per-attempt random value (~40-bit Crockford base32 string)
	// written into both this WAL entry and the PVE user's comment field at
	// creation time. walRollbackUser compares the user's live comment against
	// this nonce before deleting: a mismatch means the userid is owned by a
	// foreign/pre-existing user (e.g. a colliding legacy account) and must NOT
	// be deleted. This prevents the stale-WAL foreign-user-deletion class.
	Nonce string `json:"nonce" mapstructure:"nonce"`
}

// walRollback is registered as framework.Backend.WALRollback.
// The Vault framework calls it for any WAL entry that is older than
// WALRollbackMinAge and has not been committed (deleted) by a successful
// issuance path.
//
// WAL cleanup discipline (from AGENTS.md):
//   - ErrUserNotFound from DeleteUser → success (idempotent; PVE returns HTTP 500
//   - body "no such user" for an already-absent user — treat as gone).
//   - Any other DeleteUser error → return the error so the SDK retries the
//     rollback on the next sweep. Do NOT call DeleteWAL — leave the WAL entry
//     in place so it gets retried. Never orphan a user with no WAL entry.
//   - Unknown WAL kind → return an error so the operator is alerted via the
//     Vault audit log; do not silently swallow unknown entries.
//
// Signature matches framework.WALRollbackFunc:
//
//	func(context.Context, *logical.Request, string, interface{}) error
func (b *backend) walRollback(ctx context.Context, req *logical.Request, kind string, data interface{}) error {
	switch kind {
	case walTypeUser:
		return b.walRollbackUser(ctx, req, data)
	case walTypeRotation:
		return b.walRollbackRotation(ctx, req, data)
	default:
		return fmt.Errorf("proxmox: walRollback: unknown WAL kind %q", kind)
	}
}

func (b *backend) walRollbackRotation(ctx context.Context, req *logical.Request, data interface{}) error {
	var state rotationState
	if err := mapstructure.Decode(data, &state); err != nil {
		return fmt.Errorf("proxmox: rotation WAL decode: %w", err)
	}
	oldUser, oldToken, err := splitTokenID(state.OldTokenID)
	if err != nil || state.NewTokenID == "" {
		return fmt.Errorf("proxmox: malformed rotation WAL")
	}
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil || cfg == nil {
		return fmt.Errorf("proxmox: rotation recovery config: %w", err)
	}
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return err
	}
	switch cfg.TokenID {
	case state.OldTokenID:
		_, newToken, splitErr := splitTokenID(state.NewTokenID)
		if splitErr != nil {
			return splitErr
		}
		err = client.DeleteToken(ctx, oldUser, newToken)
	case state.NewTokenID:
		err = client.DeleteToken(ctx, oldUser, oldToken)
	default:
		return fmt.Errorf("proxmox: rotation recovery found inconsistent token ID")
	}
	if err != nil && !errors.Is(err, pveapi.ErrTokenNotFound) {
		return err
	}
	if err := req.Storage.Delete(ctx, rotationStorageKey); err != nil {
		return err
	}
	return nil
}

// walRollbackUser handles rollback for walTypeUser entries.
// It decodes the map[string]interface{} payload into a walUser, then performs
// nonce-based ownership verification before attempting to delete the PVE user.
//
// Ownership verification prevents deleting a foreign user that coincidentally
// holds the same userid as a stale WAL entry:
//  1. GetUser: if ErrUserNotFound → already gone, return nil.
//  2. Compare user's comment to WAL Nonce:
//     - match → our orphan → DeleteUser.
//     - mismatch or empty comment → foreign user or ownership lost → log Error
//     (terminal: WAL is dropped, user leaks until manual removal), return nil.
//  3. GetUser transient error → return error (framework retries).
func (b *backend) walRollbackUser(ctx context.Context, req *logical.Request, data interface{}) error {
	// WALEntry.Data is JSON-decoded into interface{}, which arrives here as
	// map[string]interface{}. mapstructure.Decode handles the conversion.
	var entry walUser
	if err := mapstructure.Decode(data, &entry); err != nil {
		return fmt.Errorf("proxmox: walRollback user: decode WAL payload: %w", err)
	}

	if entry.UserID == "" {
		return fmt.Errorf("proxmox: walRollback user: WAL payload missing user_id")
	}

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		// Config may have been deleted; log and return error so the framework
		// retries. Do not delete the WAL entry.
		b.Logger().Warn("walRollback: could not get PVE client; will retry", "error", err)
		return fmt.Errorf("proxmox: walRollback user %q: get client: %w", entry.UserID, err)
	}

	// Ownership verification: GetUser before Delete.
	// If the user is already absent we are done (idempotent success).
	// If the user exists, compare its comment to the WAL nonce to confirm we
	// created it and not a foreign/pre-existing account with the same userid.
	info, getUserErr := client.GetUser(ctx, entry.UserID)
	if getUserErr != nil {
		if errors.Is(getUserErr, pveapi.ErrUserNotFound) {
			// User is already absent — nothing to clean up.
			b.Logger().Info("walRollback: PVE user already absent (idempotent)", "userid", entry.UserID)
			return nil
		}
		// Transient error (network, 403, etc.) — return so the framework retries.
		// Leave the WAL entry in place.
		b.Logger().Warn("walRollback: GetUser failed; will retry", "userid", entry.UserID, "error", getUserErr)
		return fmt.Errorf("proxmox: walRollback user %q: GetUser: %w", entry.UserID, getUserErr)
	}

	// Nonce / ownership check: the user's comment must match the WAL nonce.
	// If the nonce is absent (old WAL entries written before this change) or the
	// comment does not match, this is a foreign user — do NOT delete it.
	if entry.Nonce == "" || info.Comment != entry.Nonce {
		b.Logger().Error(
			"walRollback: user comment does not match WAL nonce; treating as foreign user and dropping WAL WITHOUT delete — "+
				"if this user was ours (comment altered or dropped on create) it will leak as a dead user until manually removed",
			"userid", entry.UserID,
			"wal_nonce", entry.Nonce,
			"user_comment", info.Comment,
		)
		// Return nil so the framework drops this WAL entry without touching the user.
		return nil
	}

	// Nonce matches — this is our orphaned user; proceed with deletion.
	err = client.DeleteUser(ctx, entry.UserID)
	if err == nil {
		// User deleted successfully.
		b.Logger().Info("walRollback: deleted orphaned PVE user", "userid", entry.UserID)
		return nil
	}

	// ErrUserNotFound: already absent. Treat as success.
	if errors.Is(err, pveapi.ErrUserNotFound) {
		b.Logger().Info("walRollback: PVE user already absent (idempotent)", "userid", entry.UserID)
		return nil
	}

	// Any other error (network failure, 403, transient PVE error): return the
	// error so the framework retries on the next rollback sweep. The WAL entry
	// is NOT deleted — it remains for retry.
	b.Logger().Warn("walRollback: DeleteUser failed; will retry", "userid", entry.UserID, "error", err)
	return fmt.Errorf("proxmox: walRollback user %q: DeleteUser: %w", entry.UserID, err)
}
