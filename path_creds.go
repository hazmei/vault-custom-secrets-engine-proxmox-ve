// Package proxmox — credentials path: <mount>/creds/:role (ReadOperation, mutating).
//
// handleCredsRead implements Design A (confirmed correct against SDK):
//   - Load role + config.
//   - Compute effective TTL via framework.CalculateTTL (with correct fallback chain).
//   - Refuse issuance if effective TTL resolves to 0/unlimited (Locked Decision #9).
//   - expire = lease-end-unix + 60s grace.
//   - Bounded retry loop with per-attempt WAL + nonce:
//     generate nonce → PutWAL{UserID,Nonce} → CreateUser{Comment=nonce} →
//     on ErrConflict → DeleteWAL(walID) + retry.
//   - Read-back GetUser: assert group membership; soft-check comment==nonce.
//   - Token mode: CreateToken with privsep=0 (MANDATORY).
//     Password mode: no token is minted; the password is supplied on the
//     CreateUser call itself and is live as soon as that call returns.
//   - On success: DeleteWAL(walID) before returning Secret.
//   - On DeleteWAL failure: best-effort DeleteUser then return error.
//
// ForwardPerformanceStandby and ForwardPerformanceSecondary are set on the
// ReadOperation so the request is forwarded to the active node BEFORE any
// PVE call, preventing duplicate user creation on standbys.
//
// See docs/ARCHITECTURE.md §Issuance and AGENTS.md §Credential Lifecycle.
package proxmox

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	pveapi "github.com/hazmei/vault-plugin-secrets-proxmox/internal/pveapi"
)

const (
	// maxCollisionRetries is the maximum number of userid suffix attempts before
	// giving up with an internal error. Each attempt uses a fresh 8-char base32
	// random suffix (~40 bits entropy); collisions are extremely unlikely in
	// practice, but a finite bound prevents infinite loops.
	maxCollisionRetries = 5

	// expireGraceSecs is added to the computed lease-end Unix timestamp when
	// setting the PVE user account expiry. The grace period ensures the PVE
	// credential remains valid for the full Vault-issued TTL even if there is
	// slight clock drift between the Vault server and the PVE cluster, or
	// if Vault processes the final seconds of a lease slightly after the TTL.
	expireGraceSecs = 60

	// leaseTokenID is the fixed tokenid suffix used for the per-lease API
	// token. Scoped per-user (each lease gets a unique userid), so there is
	// no collision risk between leases.
	leaseTokenID = "lease"
)

// pathCreds returns the framework.Path for <mount>/creds/:role.
func pathCreds(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("name"),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "proxmox",
			OperationSuffix: "credentials",
		},
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Role name to issue credentials for.",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.handleCredsRead,
				// REQUIRED: forward mutating ReadOperation to the active node BEFORE
				// any PVE call. Without this, a standby node would execute CreateUser
				// locally, potentially issuing duplicate PVE users.
				ForwardPerformanceStandby:   true,
				ForwardPerformanceSecondary: true,
			},
		},
		HelpSynopsis:    "Issue a dynamic Proxmox VE API token.",
		HelpDescription: "Reads credentials for the named role. Creates a synthetic PVE user (added to the role's group), mints a privsep=0 API token, and returns the token credentials. The credential is valid until the Vault lease expires.",
	}
}

// handleCredsRead handles GET/READ to <mount>/creds/:role.
//
// This is a ReadOperation that MUTATES PVE state (standard dynamic-secrets convention).
// The ForwardPerformanceStandby/ForwardPerformanceSecondary flags on the PathOperation
// ensure the Vault framework routes this to the active node before execution.
func (b *backend) handleCredsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("name").(string)

	// Step 1: load role (nil → 404-style nil response).
	role, err := getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, fmt.Errorf("proxmox: creds/%s: load role: %w", roleName, err)
	}
	if role == nil {
		return logical.ErrorResponse("role %q not found; write a role to <mount>/roles/%s first", roleName, roleName), nil
	}

	// Load config.
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("proxmox: creds/%s: load config: %w", roleName, err)
	}
	if cfg == nil {
		return logical.ErrorResponse("no config found; write config to <mount>/config first"), nil
	}

	// Step 2: compute effective TTL and max_ttl via framework.CalculateTTL.
	// TTL fallback chain: role.ttl → config.default_ttl → Vault system default.
	// MaxTTL fallback chain: role.max_ttl → config.default_max_ttl → Vault system max.
	// CRITICAL: config.default_ttl is a FALLBACK, not a cap. Using role.ttls(cfg)
	// correctly implements this: returns 0 (unset) when neither role nor config has a value,
	// letting CalculateTTL fall back to the system default.
	backendTTL, backendMaxTTL := role.ttls(cfg)

	// CalculateTTL: increment=0 (no caller-requested increment at issuance — creds
	// path declares no ttl field), period=0, explicitMaxTTL=0, startTime=zero (now).
	ttl, _, err := framework.CalculateTTL(
		b.System(),
		0,             // increment: no caller-requested increment at issuance
		backendTTL,    // backendTTL: role.ttl → config.default_ttl → 0 (system default)
		0,             // period: not used
		backendMaxTTL, // backendMaxTTL: role.max_ttl → config.default_max_ttl → 0 (system max)
		0,             // explicitMaxTTL: not used
		time.Time{},   // startTime: zero = now
	)
	if err != nil {
		return nil, fmt.Errorf("proxmox: creds/%s: CalculateTTL: %w", roleName, err)
	}

	// Locked Decision #9: refuse issuance if TTL is zero (unlimited credential).
	// PVE expire=0 means no expiry — we never mint non-expiring credentials.
	if ttl <= 0 {
		return logical.ErrorResponse(
			"effective TTL is zero (unlimited); refusing to issue non-expiring PVE credentials — " +
				"set a ttl on the role or configure default_ttl on the engine mount",
		), nil
	}

	// Compute effective max_ttl for storage in InternalData (governance ceiling for renewals).
	// cappedMaxTTL treats 0 as "unset", avoiding the zero-collapse trap.
	effectiveMaxTTL := cappedMaxTTL(backendMaxTTL, b.System().MaxLeaseTTL())

	// Step 3: expire = lease-end-unix + 60s grace.
	leaseEnd := time.Now().Add(ttl)
	expireUnix := leaseEnd.Unix() + expireGraceSecs

	// Get PVE client.
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("proxmox: creds/%s: get PVE client: %w", roleName, err)
	}

	// Step 3b: password mode — generate the credential BEFORE the retry loop.
	// One password serves every suffix attempt: a collided attempt creates
	// nothing in PVE, so no attempt can leak or strand it. The value is live
	// only once CreateUser succeeds.
	passwordMode := role.Mode == modePassword
	var password string
	if passwordMode {
		version, versionErr := client.GetVersionInfo(ctx)
		if versionErr != nil {
			return nil, fmt.Errorf("proxmox: creds/%s: verify password-mode PVE build: %w", roleName, versionErr)
		}
		if version.Version != passwordVerifiedVersion || version.RepoID != passwordVerifiedRepoID {
			// Operator/environment condition, not an engine fault: surface as a
			// 400-class response like the zero-TTL refusal above, not a 500.
			return logical.ErrorResponse(
				"password mode requires verified PVE build %s; this cluster reports version=%q repoid=%q "+
					"(docs/PVE_PROBES.md Probe P0 records password behavior only on the verified build)",
				passwordVerifiedBuild, version.Version, version.RepoID,
			), nil
		}
		password, err = generatePassword()
		if err != nil {
			// generatePassword never puts generated material in its error.
			return nil, fmt.Errorf("proxmox: creds/%s: %w", roleName, err)
		}
	}

	// Step 4: bounded retry loop over random suffixes.
	var (
		userid string
		walID  string
		nonce  string // hoisted so post-loop read-back can check comment==nonce
	)

	for attempt := 0; attempt < maxCollisionRetries; attempt++ {
		suffix, suffixErr := randomSuffix()
		if suffixErr != nil {
			return nil, fmt.Errorf("proxmox: creds/%s: generate random suffix: %w", roleName, suffixErr)
		}

		userid = buildUserID(role.UserPrefix, roleName, suffix, role.Realm)

		// Generate a per-attempt nonce for ownership verification.
		// The nonce is written to both the WAL entry and the PVE user's comment
		// field. walRollbackUser compares the two at rollback time: a mismatch
		// means the userid belongs to a foreign user (collision with a pre-existing
		// account) and must not be deleted.
		// The walCommentPrefix makes the marker self-documenting in the PVE UI.
		// Both walUser.Nonce and CreateUserRequest.Comment store the SAME full
		// prefixed string so the comparison in walRollbackUser remains a simple
		// equality check.
		rawNonce, nonceErr := randomSuffix()
		if nonceErr != nil {
			return nil, fmt.Errorf("proxmox: creds/%s: generate nonce: %w", roleName, nonceErr)
		}
		nonce = walCommentPrefix + rawNonce

		// Step 4a: Write WAL before CreateUser. Capture the RETURNED id (random UUID).
		// This id is used for DeleteWAL — it is NOT the userid.
		var walErr error
		walID, walErr = framework.PutWAL(ctx, req.Storage, walTypeUser, walUser{UserID: userid, Nonce: nonce})
		if walErr != nil {
			return nil, fmt.Errorf("proxmox: creds/%s: PutWAL for %q: %w", roleName, userid, walErr)
		}

		// Step 4b: CreateUser with groups=<role.group>, expire, and Comment=nonce.
		// The nonce in Comment enables walRollbackUser to verify ownership before
		// deleting, closing the stale-WAL foreign-user-deletion class.
		// In password mode the credential is LIVE the moment this call returns
		// 200 — before the group read-back and before DeleteWAL. Every failure
		// after this point must delete the user (cleanupUser), not just log.
		createErr := client.CreateUser(ctx, pveapi.CreateUserRequest{
			UserID:   userid,
			Groups:   role.Group, // single CSV field (only one group per role)
			Expire:   expireUnix,
			Enable:   true,
			Comment:  nonce,    // ownership marker for walRollbackUser
			Password: password, // empty in token mode
		})

		if createErr == nil {
			// Success — break out of retry loop.
			break
		}

		if errors.Is(createErr, pveapi.ErrConflict) {
			// Userid collision (HTTP 500 body "already exists"): delete the WAL entry
			// for THIS attempt and try again with a new suffix.
			b.Logger().Warn("creds: userid collision, retrying with new suffix",
				"userid", userid, "attempt", attempt+1)
			if delErr := framework.DeleteWAL(ctx, req.Storage, walID); delErr != nil {
				// DeleteWAL failure on the collision path is a hard stop.
				// The stale WAL entry names a userid we did NOT create (the
				// conflicting user belongs to another lease or external entity).
				// walRollbackUser's nonce/comment ownership check prevents it
				// from deleting the foreign colliding user: the WAL entry's nonce
				// will not match the foreign user's comment, so walRollback will
				// drop the WAL entry without touching the user. However, we still
				// surface the DeleteWAL failure so the operator is aware.
				b.Logger().Error("creds: DeleteWAL after collision failed; aborting issuance",
					"walID", walID, "userid", userid, "error", delErr)
				return nil, fmt.Errorf("proxmox: creds/%s: DeleteWAL after collision for %q: %w", roleName, userid, delErr)
			}
			walID = "" // clear so exhaustion path knows last attempt was cleaned
			continue
		}

		// Step 4c: Non-conflict error from CreateUser — leave WAL for rollback.
		// Do NOT DeleteWAL — walRollback will retry.
		return nil, wrapAdminUnauthenticated(fmt.Errorf("proxmox: creds/%s: CreateUser %q: %w", roleName, userid, createErr))
	}

	// Collision exhaustion check: if walID is empty, all attempts collided and
	// were cleaned up. Return an internal error.
	if walID == "" {
		return nil, fmt.Errorf("proxmox: creds/%s: exhausted %d userid suffix attempts (all collisions); try again", roleName, maxCollisionRetries)
	}

	// From here on, userid is created in PVE and walID is a live WAL entry.
	// All cleanup (on error) must follow the WAL discipline:
	//   - DeleteUser; then DeleteWAL ONLY if DeleteUser returned nil or ErrUserNotFound.
	//   - If DeleteUser fails transiently, LEAVE WAL for walRollback to retry.

	// Step 5: Read-back — GetUser, assert group membership.
	info, err := client.GetUser(ctx, userid)
	if err != nil {
		b.Logger().Warn("creds: GetUser read-back failed; cleaning up", "userid", userid, "error", err)
		if cleanErr := b.cleanupUser(ctx, req.Storage, userid, walID); cleanErr != nil {
			b.Logger().Error("creds: compensation failed after GetUser failure; WAL left for walRollback",
				"userid", userid, "walID", walID, "cleanup_error", cleanErr)
		}
		return nil, wrapAdminUnauthenticated(fmt.Errorf("proxmox: creds/%s: GetUser read-back %q: %w", roleName, userid, err))
	}
	if !containsGroup(info.Groups, role.Group) {
		b.Logger().Warn("creds: group read-back assertion failed; cleaning up",
			"userid", userid, "expected_group", role.Group, "actual_groups", info.Groups)
		if cleanErr := b.cleanupUser(ctx, req.Storage, userid, walID); cleanErr != nil {
			b.Logger().Error("creds: compensation failed after group assertion failure; WAL left for walRollback",
				"userid", userid, "walID", walID, "cleanup_error", cleanErr)
		}
		return nil, fmt.Errorf(
			"proxmox: creds/%s: group read-back assertion failed: user %q not in group %q (groups: %v); "+
				"verify the group exists and the admin token has User.Modify at /access/groups/<group> with propagate=1",
			roleName, userid, role.Group, info.Groups,
		)
	}

	// Password mode: a nonce mismatch is FATAL (docs/IMPLEMENTATION_PLAN.md P1
	// comment read-back policy). The credential already authenticates, and a
	// lost marker means walRollbackUser can no longer prove ownership, so a
	// crash here would strand a LIVE credential until the PVE expire backstop.
	// Delete the user now and fail issuance rather than hand out a credential
	// whose crash-recovery path is already broken.
	//
	// If that DeleteUser fails transiently the WAL entry is retained, but
	// walRollback will DROP it without deleting the user (the nonce does not
	// match). Cleanup is then bounded by the PVE expire backstop or manual
	// operator action — documented in README.md and docs/ARCHITECTURE.md.
	if passwordMode && info.Comment != nonce {
		b.Logger().Error("creds: user comment does not match WAL nonce in password mode; deleting the live credential and failing issuance",
			"userid", userid, "expected", nonce, "actual", info.Comment)
		if cleanErr := b.cleanupUser(ctx, req.Storage, userid, walID); cleanErr != nil {
			b.Logger().Error("creds: compensation failed after password-mode comment mismatch; the live credential may persist until the PVE expire backstop",
				"userid", userid, "walID", walID, "cleanup_error", cleanErr)
		}
		return nil, fmt.Errorf(
			"proxmox: creds/%s: comment read-back mismatch for %q in password mode; "+
				"the user was deleted and no credential was issued — do not hand-edit the comment field on vault-* users",
			roleName, userid,
		)
	}

	// M2: Soft-check that the comment survived the CreateUser round-trip.
	// PVE could truncate or drop the comment field (as it can silently drop
	// groups); if it does, walRollbackUser will mis-identify the user as
	// foreign and skip automatic cleanup — the user leaks until the PVE
	// expire backstop fires. We do NOT fail issuance here (the credential
	// is otherwise valid), but we emit a Warn so operators are alerted.
	// Only crash-recovery (walRollback) is degraded; the normal revocation
	// path is unaffected.
	if !passwordMode && info.Comment != nonce {
		b.Logger().Warn("creds: user comment does not match WAL nonce after create; walRollback cleanup will not be able to verify ownership",
			"userid", userid,
			"expected", nonce,
			"actual", info.Comment,
		)
	}

	// Step 6: CreateToken with privsep=0 (MANDATORY — sent by the client, not this caller).
	// Password mode mints NO token: the password on the synthetic user is the
	// credential, and it inherits the group-derived role directly.
	var tokenSecret string
	if !passwordMode {
		secret, tokenErr := client.CreateToken(ctx, userid, leaseTokenID)
		if tokenErr != nil {
			b.Logger().Warn("creds: CreateToken failed; cleaning up", "userid", userid, "error", tokenErr)
			if cleanErr := b.cleanupUser(ctx, req.Storage, userid, walID); cleanErr != nil {
				b.Logger().Error("creds: compensation failed after CreateToken failure; WAL left for walRollback",
					"userid", userid, "walID", walID, "cleanup_error", cleanErr)
			}
			return nil, wrapAdminUnauthenticated(fmt.Errorf("proxmox: creds/%s: CreateToken for %q: %w", roleName, userid, tokenErr))
		}
		tokenSecret = secret
	}

	// Step 7: SUCCESS — DeleteWAL before returning the Secret.
	// If DeleteWAL fails: best-effort DeleteUser, then return error.
	// (All work including WAL delete must complete before returning Secret.)
	if err := framework.DeleteWAL(ctx, req.Storage, walID); err != nil {
		b.Logger().Error("creds: DeleteWAL failed on success path; cleaning up",
			"walID", walID, "userid", userid, "error", err)
		// Best-effort cleanup: delete the user (and implicitly the token).
		if delErr := client.DeleteUser(ctx, userid); delErr != nil && !errors.Is(delErr, pveapi.ErrUserNotFound) {
			b.Logger().Warn("creds: best-effort DeleteUser after DeleteWAL failure also failed",
				"userid", userid, "error", delErr)
		}
		return nil, fmt.Errorf("proxmox: creds/%s: DeleteWAL failed after successful issuance — credential not returned to prevent orphan without WAL: %w", roleName, err)
	}

	// Step 8: Build and return the Secret.
	//
	// InternalData is IDENTICAL in both modes — pve_userid, group,
	// effective_max_ttl (nanoseconds as int64), role_name (TTL fallback on
	// renewal), expire (Unix epoch) — so renew and revoke are mode-independent.
	// The password is NEVER placed in InternalData, the WAL, or a log line.
	internalData := map[string]interface{}{
		"pve_userid":        userid,
		"group":             role.Group,
		"effective_max_ttl": int64(effectiveMaxTTL), // nanoseconds
		"role_name":         roleName,               // for TTL fallback on renewal
		"expire":            expireUnix,             // Unix epoch; rewritten on each renewal
	}

	var resp *logical.Response
	if passwordMode {
		// Password mode contract: exactly user_id and password. No token fields.
		resp = secretPassword(b).Response(
			map[string]interface{}{
				"user_id":  userid,
				"password": password, // returned once; never readable again
			},
			internalData,
		)
		b.Logger().Info("creds: issued PVE dynamic password",
			"role", roleName,
			"userid", userid,
			"ttl", ttl,
		)
	} else {
		// The full PVEAPIToken identifier format is: <userid>!<tokenid>
		// Used in the Authorization header as: PVEAPIToken=<token_id>=<token_secret>
		tokenID := userid + "!" + leaseTokenID
		resp = secretToken(b).Response(
			map[string]interface{}{
				"token_id":     tokenID,
				"token_secret": tokenSecret, // one-time; never readable again
				"user_id":      userid,
			},
			internalData,
		)
		b.Logger().Info("creds: issued PVE dynamic token",
			"role", roleName,
			"userid", userid,
			"token_id", tokenID,
			"ttl", ttl,
		)
	}

	// Set the lease TTL and MaxTTL on the Secret.
	resp.Secret.TTL = ttl
	resp.Secret.MaxTTL = effectiveMaxTTL

	return resp, nil
}

// cleanupUser performs best-effort PVE user deletion and conditional WAL cleanup.
//
// WAL cleanup discipline (AGENTS.md):
//   - DeleteWAL ONLY if DeleteUser returned nil or ErrUserNotFound.
//   - If DeleteUser fails transiently, LEAVE the WAL entry for walRollback to retry.
//   - Never orphan a user with no WAL entry.
//
// Returns the DeleteUser error (nil if idempotent ErrUserNotFound). Callers
// typically ignore the return value since this is called on the error path.
func (b *backend) cleanupUser(ctx context.Context, storage logical.Storage, userid, walID string) error {
	client, err := b.getClient(ctx, storage)
	if err != nil {
		b.Logger().Warn("cleanupUser: could not get PVE client; WAL left for rollback",
			"userid", userid, "walID", walID, "error", err)
		return err
	}

	deleteErr := client.DeleteUser(ctx, userid)
	if deleteErr == nil || errors.Is(deleteErr, pveapi.ErrUserNotFound) {
		// User deleted (or already absent) — safe to clean the WAL entry.
		if walID != "" {
			if delWALErr := framework.DeleteWAL(ctx, storage, walID); delWALErr != nil {
				b.Logger().Warn("cleanupUser: DeleteWAL failed after successful DeleteUser",
					"userid", userid, "walID", walID, "error", delWALErr)
			}
		}
		return nil
	}

	// DeleteUser failed transiently — LEAVE the WAL entry for walRollback.
	b.Logger().Warn("cleanupUser: DeleteUser failed; WAL left for rollback",
		"userid", userid, "walID", walID, "error", deleteErr)
	return deleteErr
}

// wrapAdminUnauthenticated adds an operator-facing diagnostic for expired,
// revoked, or invalid PVE admin tokens while preserving errors.Is matching.
func wrapAdminUnauthenticated(err error) error {
	if err == nil || !errors.Is(err, pveapi.ErrUnauthenticated) {
		return err
	}
	return fmt.Errorf("admin token unauthenticated — check config credentials: %w", err)
}
