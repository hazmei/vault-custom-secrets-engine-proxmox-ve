// Package proxmox — secret type definition for the dynamic PVE API token.
//
// secretToken registers the "token" secret type with the Vault framework.
// It defines:
//   - Fields describing the returned credential (token_id, token_secret, user_id).
//   - A non-nil Renew callback (required — a nil Renew causes Secret.Renewable()
//     to return false, which makes leases non-renewable).
//   - A non-nil Revoke callback that performs an idempotent DeleteUser, cascading
//     to remove all tokens, group memberships, and ACL entries.
//
// Full renew implementation (UpdateUser full-replace with expire+groups+enable+append)
// is provided here. Full revoke is also implemented here via idempotent DeleteUser.
//
// InternalData keys consumed by Renew/Revoke:
//   - "pve_userid"        (string) — fully-qualified PVE userid
//   - "group"             (string) — PVE group name (needed for full-replace renewal)
//   - "effective_max_ttl" (int64)  — nanoseconds; governs renewal ceiling
//   - "role_name"         (string) — role name; used to load role TTL for no-increment renewal
//   - "expire"            (int64)  — Unix epoch; rewritten on each renewal to track PVE state
//
// See docs/ARCHITECTURE.md §Lease Renewal and §Revocation for the full spec.
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

// secretTypeToken is the Vault secret type identifier for PVE dynamic tokens.
// Registered in framework.Backend.Secrets so the framework can route
// renew/revoke calls to the correct handlers.
const secretTypeToken = "token"

// secretToken builds the *framework.Secret for PVE dynamic tokens.
// Must be added to framework.Backend.Secrets (done in backend.go Phase-3 wiring).
func secretToken(b *backend) *framework.Secret {
	return &framework.Secret{
		Type: secretTypeToken,

		// Fields describes the data returned in the credential response (resp.Data).
		// token_secret is intentionally omitted from Fields metadata — it is
		// one-time, non-reproducible, and must never be read back after issuance.
		// It IS present in resp.Data at issue time (written by path_creds.go), but
		// registering it in Fields metadata is unnecessary and could mislead callers
		// into expecting it on renewal responses.
		Fields: map[string]*framework.FieldSchema{
			"token_id": {
				Type:        framework.TypeString,
				Description: "Full PVEAPIToken identifier: <user>@<realm>!<tokenid>. Use in the Authorization header: PVEAPIToken=<token_id>=<token_secret>.",
			},
			"token_secret": {
				Type:        framework.TypeString,
				Description: "Proxmox VE API token secret (UUID). One-time value returned only at issuance — never readable again.",
			},
			"user_id": {
				Type:        framework.TypeString,
				Description: "Fully-qualified PVE userid of the synthetic lease user (e.g. vault-myrole-a3b7x2kp@pve).",
			},
		},

		// Renew must be non-nil — Secret.Renewable() returns (Renew != nil), so a
		// nil Renew silently makes every issued lease non-renewable. Full renewal
		// logic: read pve_userid+group+effective_max_ttl+role_name+expire from
		// InternalData, compute new TTL via CalculateTTL (honoring role.ttl when
		// the role is still present), PUT /access/users (full-replace with
		// expire+groups+enable+append=1), read-back group assertion, return updated Secret.
		Renew: b.secretTokenRenew,

		// Revoke performs idempotent DeleteUser, cascading to remove tokens,
		// group memberships, and ACL entries. ErrUserNotFound (HTTP 500 + body
		// "no such user") is treated as success for idempotent revocation.
		Revoke: b.secretTokenRevoke,
	}
}

// secretTokenRenew handles lease renewal for PVE dynamic tokens.
//
// Steps:
//  1. Extract pve_userid, group, effective_max_ttl, role_name from InternalData.
//  2. Load role to obtain role.ttl for use as backendTTL.
//     - role found → backendTTL = role.ttls(cfg).backendTTL (honors role.ttl).
//     - roleName == "" (old lease, no role_name) → backendTTL = req.Secret.TTL
//     (fall back to the lease's current TTL, per documented behavior).
//     - role == nil (role deleted since issuance) → backendTTL = req.Secret.TTL
//     (fall back to the lease's current TTL; do NOT hard-fail outstanding leases).
//     An explicit positive increment still wins (CalculateTTL uses increment when > 0).
//  3. Compute new TTL via framework.CalculateTTL (honors increment and effective_max_ttl).
//  4. Refuse renewal if new TTL is zero.
//  5. Pre-update GetUser: refuse renewal if the user is currently disabled (an
//     operator may have disabled it for incident response; we must not re-enable it).
//  6. UpdateUser: PUT /access/users/{userid} with expire+groups+enable+append=1
//     (FULL-REPLACE — omitting groups wipes membership; confirmed PVE 9.2.10 Probe 7).
//  7. Read-back: GetUser asserts group membership survived the PUT.
//  8. Rewrite expire in InternalData to the newExpire computed this renewal.
//  9. Return updated Secret with new TTL/MaxTTL.
func (b *backend) secretTokenRenew(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	// Step 1: extract from InternalData.
	userid, group, effectiveMaxTTL, roleName, err := extractLeaseInternalData(req.Secret.InternalData)
	if err != nil {
		return nil, fmt.Errorf("proxmox: renew: %w", err)
	}

	// Step 2: load role for TTL fallback.
	// Default: fall back to the lease's current TTL so a no-increment renewal on a
	// deleted or pre-role_name lease does not collapse to the mount default.
	backendTTL := req.Secret.TTL
	if roleName != "" {
		cfg, cfgErr := getConfig(ctx, req.Storage)
		if cfgErr != nil {
			return nil, fmt.Errorf("proxmox: renew: load config: %w", cfgErr)
		}
		if cfg != nil {
			role, roleErr := getRole(ctx, req.Storage, roleName)
			if roleErr != nil {
				return nil, fmt.Errorf("proxmox: renew: load role %q: %w", roleName, roleErr)
			}
			if role != nil {
				// Role still exists: use its configured TTL as the backend default.
				backendTTL, _ = role.ttls(cfg)
			}
			// If role is nil (deleted since issuance): backendTTL keeps the
			// lease's current TTL — do NOT hard-fail renewal; outstanding leases
			// must still renew and be revocable.
		}
	}
	// roleName == "": old lease written before role_name was added to InternalData.
	// backendTTL is already set to req.Secret.TTL (the default above).

	// Step 3: compute new TTL.
	// CalculateTTL args: sysView, increment, backendTTL (role.ttl or lease-TTL fallback),
	// period=0, backendMaxTTL=effectiveMaxTTL, explicitMaxTTL=0, startTime=IssueTime.
	// An explicit positive increment from the renewal request overrides backendTTL
	// (CalculateTTL uses increment when > 0).
	ttl, warnings, err := framework.CalculateTTL(
		b.System(),
		req.Secret.Increment, // requested increment from the renewal request
		backendTTL,           // role.ttl if role exists; lease current TTL if role gone/absent
		0,                    // period: not used
		effectiveMaxTTL,      // backendMaxTTL: the governance ceiling captured at issue time
		0,                    // explicitMaxTTL: not used
		req.Secret.IssueTime, // startTime: so total lifetime ≤ IssueTime + effectiveMaxTTL
	)
	if err != nil {
		return nil, fmt.Errorf("proxmox: renew: CalculateTTL: %w", err)
	}

	// Step 4: refuse if TTL collapsed to zero.
	if ttl <= 0 {
		return nil, fmt.Errorf("proxmox: renew: effective TTL is zero or past max; cannot renew")
	}

	newExpire := time.Now().Add(ttl).Unix() + expireGraceSecs // +grace, same as issuance

	// Step 5: Get PVE client and perform a pre-update GetUser to check Enable.
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("proxmox: renew: get PVE client: %w", err)
	}

	// Pre-update read: refuse renewal if the user is currently disabled.
	// Renewal sends Enable:true, which would silently undo an operator's deliberate
	// containment (e.g. disabling a suspected-compromised synthetic user for incident
	// response). We must not re-enable a user that an operator has deliberately disabled.
	//
	// NOTE (TOCTOU): an operator disabling the user BETWEEN this GetUser and the
	// UpdateUser below will still be re-enabled by the update. The guard reduces
	// but does not eliminate the window; no conditional-update PVE API exists.
	preInfo, preErr := client.GetUser(ctx, userid)
	if preErr != nil {
		return nil, fmt.Errorf("proxmox: renew: pre-update GetUser %q: %w", userid, preErr)
	}
	if !preInfo.Enable {
		return nil, fmt.Errorf(
			"proxmox: renew: user %q is disabled; refusing to re-enable via renewal — "+
				"an operator may have disabled it for incident response; revoke the lease instead",
			userid,
		)
	}

	// Step 6: UpdateUser — full-replace with expire+groups+enable+append=1.
	if updateErr := client.UpdateUser(ctx, pveapi.UpdateUserRequest{
		UserID: userid,
		Expire: newExpire,
		Groups: group,
		Enable: true,
		Append: true, // MANDATORY on renewal — omitting defaults to replace (append=0)
	}); updateErr != nil {
		return nil, fmt.Errorf("proxmox: renew: UpdateUser %q: %w", userid, updateErr)
	}

	// Step 7: post-update read-back — assert group membership survived the full-replace PUT.
	info, err := client.GetUser(ctx, userid)
	if err != nil {
		return nil, fmt.Errorf("proxmox: renew: GetUser %q read-back: %w", userid, err)
	}
	if !containsGroup(info.Groups, group) {
		return nil, fmt.Errorf("proxmox: renew: group read-back assertion failed: user %q not in group %q after UpdateUser (groups: %v)", userid, group, info.Groups)
	}
	// Soft cardinality check: PVE group membership is a set (no duplicates), so len>1
	// means the user is in multiple groups, which is unexpected for a synthetic lease user.
	// This is not a hard failure — the containsGroup assertion above is the hard gate.
	if len(info.Groups) != 1 {
		b.Logger().Warn("proxmox: renew: unexpected group cardinality on synthetic lease user",
			"userid", userid, "groups", info.Groups)
	}

	// Step 8: rewrite expire in InternalData to track the PVE user state.
	// This keeps the stored expire consistent with reality across renewals.
	req.Secret.InternalData["expire"] = newExpire

	// Step 9: return updated Secret.
	resp := &logical.Response{Secret: req.Secret}
	resp.Secret.TTL = ttl
	resp.Secret.MaxTTL = effectiveMaxTTL
	for _, w := range warnings {
		resp.AddWarning(w)
	}
	return resp, nil
}

// secretTokenRevoke handles lease revocation for PVE dynamic tokens.
//
// Deletes the synthetic PVE user, which cascades to remove all tokens,
// group memberships, and ACL entries in a single call. Idempotent:
// ErrUserNotFound (HTTP 500 + body "no such user") is treated as success.
func (b *backend) secretTokenRevoke(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	userid, _, _, _, err := extractLeaseInternalData(req.Secret.InternalData)
	if err != nil {
		return nil, fmt.Errorf("proxmox: revoke: %w", err)
	}

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("proxmox: revoke: get PVE client: %w", err)
	}

	err = client.DeleteUser(ctx, userid)
	if err == nil || errors.Is(err, pveapi.ErrUserNotFound) {
		// Success or already absent — idempotent.
		b.Logger().Info("secretTokenRevoke: PVE user deleted (or already absent)", "userid", userid)
		return nil, nil
	}

	// Any other error: return it so Vault retries revocation.
	return nil, fmt.Errorf("proxmox: revoke: DeleteUser %q: %w", userid, err)
}

// extractLeaseInternalData reads the required keys from InternalData.
// Returns an error if the mandatory keys (pve_userid, group, effective_max_ttl) are
// missing or have the wrong type. role_name is optional (may be absent on leases
// issued before this field was added — treat missing as "" for backward compat).
func extractLeaseInternalData(data map[string]interface{}) (userid, group string, effectiveMaxTTL time.Duration, roleName string, err error) {
	rawUserid, ok := data["pve_userid"]
	if !ok {
		err = fmt.Errorf("InternalData missing pve_userid")
		return
	}
	userid, ok = rawUserid.(string)
	if !ok || userid == "" {
		err = fmt.Errorf("InternalData pve_userid is not a non-empty string (got %T)", rawUserid)
		return
	}

	rawGroup, ok := data["group"]
	if !ok {
		err = fmt.Errorf("InternalData missing group")
		return
	}
	group, ok = rawGroup.(string)
	if !ok || group == "" {
		err = fmt.Errorf("InternalData group is not a non-empty string (got %T)", rawGroup)
		return
	}

	// effective_max_ttl is stored as int64 nanoseconds.
	rawMaxTTL, ok := data["effective_max_ttl"]
	if !ok {
		err = fmt.Errorf("InternalData missing effective_max_ttl")
		return
	}
	// JSON round-trip through InternalData may decode int64 as float64 or json.Number.
	switch v := rawMaxTTL.(type) {
	case int64:
		effectiveMaxTTL = time.Duration(v)
	case float64:
		// float64 exactly represents integer nanoseconds up to 2^53 ns (~104 days),
		// comfortably covering Vault's default 32-day max lease TTL. The int64→
		// JSON(float64)→Duration round-trip is therefore lossless for realistic TTLs
		// (worst-case ≤2 ns error only beyond ~104-day durations, negligible vs the
		// 60 s expire grace).
		effectiveMaxTTL = time.Duration(int64(v))
	case int:
		effectiveMaxTTL = time.Duration(v)
	default:
		err = fmt.Errorf("InternalData effective_max_ttl has unexpected type %T", rawMaxTTL)
		return
	}

	// role_name: optional — leases issued before this field was added will not
	// have it. Treat missing or wrong-type as "" so renew falls back to the
	// lease's current TTL (backward compatibility for pre-existing leases).
	if rawRoleName, hasRoleName := data["role_name"]; hasRoleName {
		if rn, isStr := rawRoleName.(string); isStr {
			roleName = rn
		}
		// Silently ignore wrong-type role_name (treat as absent).
	}

	return
}

// containsGroup reports whether group is present in the groups slice.
func containsGroup(groups []string, group string) bool {
	for _, g := range groups {
		if g == group {
			return true
		}
	}
	return false
}
