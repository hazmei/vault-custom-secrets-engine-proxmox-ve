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
		// logic: read pve_userid+group+effective_max_ttl from InternalData,
		// compute new TTL via CalculateTTL, PUT /access/users (full-replace with
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
//  1. Extract pve_userid, group, and effective_max_ttl from req.Secret.InternalData.
//  2. Compute new TTL via framework.CalculateTTL (honors increment and effective_max_ttl).
//  3. Refuse renewal if new TTL is zero.
//  4. UpdateUser: PUT /access/users/{userid} with expire+groups+enable+append=1
//     (FULL-REPLACE — omitting groups wipes membership; confirmed PVE 9.2.10 Probe 7).
//  5. Read-back: GetUser asserts group membership survived the PUT.
//  6. Return updated Secret with new TTL/MaxTTL.
func (b *backend) secretTokenRenew(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	// Step 1: extract from InternalData.
	userid, group, effectiveMaxTTL, err := extractLeaseInternalData(req.Secret.InternalData)
	if err != nil {
		return nil, fmt.Errorf("proxmox: renew: %w", err)
	}

	// Step 2: compute new TTL.
	// CalculateTTL args: sysView, increment, backendTTL=0, period=0,
	// backendMaxTTL=effectiveMaxTTL, explicitMaxTTL=0, startTime=IssueTime.
	// Using backendMaxTTL so the cap is respected via CalculateTTL's capping logic.
	ttl, warnings, err := framework.CalculateTTL(
		b.System(),
		req.Secret.Increment, // requested increment from the renewal request
		0,                    // backendTTL: not used on renewal; increment drives the value
		0,                    // period: not used
		effectiveMaxTTL,      // backendMaxTTL: the governance ceiling captured at issue time
		0,                    // explicitMaxTTL: not used
		req.Secret.IssueTime, // startTime: so total lifetime ≤ IssueTime + effectiveMaxTTL
	)
	if err != nil {
		return nil, fmt.Errorf("proxmox: renew: CalculateTTL: %w", err)
	}

	// Step 3: refuse if TTL collapsed to zero.
	if ttl <= 0 {
		return nil, fmt.Errorf("proxmox: renew: effective TTL is zero or past max; cannot renew")
	}

	newExpire := time.Now().Add(ttl).Unix() + 60 // +60s grace (same as issuance)

	// Step 4: UpdateUser — full-replace with expire+groups+enable+append=1.
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("proxmox: renew: get PVE client: %w", err)
	}

	if updateErr := client.UpdateUser(ctx, pveapi.UpdateUserRequest{
		UserID: userid,
		Expire: newExpire,
		Groups: group,
		Enable: true,
		Append: true, // MANDATORY on renewal — omitting defaults to replace (append=0)
	}); updateErr != nil {
		return nil, fmt.Errorf("proxmox: renew: UpdateUser %q: %w", userid, updateErr)
	}

	// Step 5: read-back — assert group membership survived the full-replace PUT.
	info, err := client.GetUser(ctx, userid)
	if err != nil {
		return nil, fmt.Errorf("proxmox: renew: GetUser %q read-back: %w", userid, err)
	}
	if !containsGroup(info.Groups, group) {
		return nil, fmt.Errorf("proxmox: renew: group read-back assertion failed: user %q not in group %q after UpdateUser (groups: %v)", userid, group, info.Groups)
	}

	// Step 6: return updated Secret.
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
	userid, _, _, err := extractLeaseInternalData(req.Secret.InternalData)
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

// extractLeaseInternalData reads the three required keys from InternalData.
// Returns an error if any key is missing or has the wrong type.
func extractLeaseInternalData(data map[string]interface{}) (userid, group string, effectiveMaxTTL time.Duration, err error) {
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
		effectiveMaxTTL = time.Duration(int64(v))
	case int:
		effectiveMaxTTL = time.Duration(v)
	default:
		err = fmt.Errorf("InternalData effective_max_ttl has unexpected type %T", rawMaxTTL)
		return
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
