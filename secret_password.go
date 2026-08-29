// Package proxmox — secret type definition for the dynamic PVE user password.
//
// secretPassword registers the "password" secret type. It is a SEPARATE secret
// type from "token" (docs/IMPLEMENTATION_PLAN.md P3): the response contract,
// the operator's handling of the value, and the issuance path differ, and
// existing token leases must keep routing to the token type unchanged.
//
// Lifecycle callbacks are deliberately SHARED with the token secret type:
// renewal and revocation act only on the synthetic PVE user recorded in the
// lease InternalData, and that user is identical in both modes.
//
//   - Renew: PUT /access/users with expire+groups+enable+append=1. Evidence from
//     pve-manager/9.2.14/a1480fa6b8d899cb (docs/PVE_PROBES.md Probe P0) confirms
//     the ORIGINAL password still authenticates after exactly this renewal shape;
//     9.2.10 has no password evidence. Renewal extends expiry only. It never
//     rotates and never returns a password.
//   - Revoke: idempotent DELETE /access/users/{userid}, cascading to the user's
//     group memberships and ACL entries.
//
// The engine never rotates a password: PUT /access/password requires a
// password-authenticated ticket, which API-token authentication cannot obtain
// (Probe P0). A caller who needs a new password revokes the lease and issues a
// new credential.
package proxmox

import (
	"github.com/hashicorp/vault/sdk/framework"
)

// secretTypePassword is the Vault secret type identifier for PVE dynamic
// user passwords. Distinct from secretTypeToken so that leases issued in
// either mode route to the correct registered secret.
const secretTypePassword = "password"

// secretPassword builds the *framework.Secret for PVE dynamic passwords.
// Registered in framework.Backend.Secrets alongside secretToken.
func secretPassword(b *backend) *framework.Secret {
	return &framework.Secret{
		Type: secretTypePassword,

		// Fields describes the credential response. The contract is exactly
		// user_id and password — no token fields are ever present in this mode.
		Fields: map[string]*framework.FieldSchema{
			"user_id": {
				Type:        framework.TypeString,
				Description: "Fully-qualified PVE userid of the synthetic lease user (e.g. vault-myrole-a3b7x2kp@pve). Use as the username for password authentication.",
			},
			"password": {
				Type:        framework.TypeString,
				Description: "Generated password for the synthetic PVE user. Returned only at issuance — the engine never reads it back and never rotates it.",
			},
		},

		// Shared with the token secret type: both act on the same synthetic PVE
		// user via the lease InternalData. Renew must be non-nil or every issued
		// lease would silently be non-renewable (Secret.Renewable() is Renew != nil).
		Renew:  b.secretTokenRenew,
		Revoke: b.secretTokenRevoke,
	}
}
