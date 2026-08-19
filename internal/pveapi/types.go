// Package pveapi — types for PVE API requests, responses, and the
// permission tree returned by GET /access/permissions.
package pveapi

import (
	"fmt"
	"strings"
)

// PermissionTree is the shape of GET /access/permissions response data.
// It maps ACL paths to a map of privilege-name → propagate-flag.
//
// The propagate flag is the integer value in the inner map:
//   - 1 = the privilege propagates to child paths
//   - 0 = the privilege applies only to the exact path
//
// Confirmed on PVE 9.2.10 (PVE_PROBES.md Probe 1): the inner value IS the
// propagate flag, not a bitmask and not mere presence.
type PermissionTree map[string]map[string]int

// HasPrivilege reports whether priv is effective at the given path.
//
// Rules (from docs/IMPLEMENTATION_PLAN.md §types.go):
//   - An exact-path entry satisfies the check regardless of propagate flag.
//   - An ancestor entry satisfies the check ONLY if its propagate flag is non-zero.
//
// The walk proceeds: path → immediate parent → ... → "/".
// This correctly catches the --propagate 0 misconfiguration at config-write
// time rather than at first issuance (confirmed on PVE 9.2.10, Probe 9).
func (t PermissionTree) HasPrivilege(path, priv string) bool {
	// Normalise: ensure no trailing slash except for root.
	path = strings.TrimRight(path, "/")
	if path == "" {
		path = "/"
	}

	current := path
	for {
		if privs, ok := t[current]; ok {
			if _, hasPerm := privs[priv]; hasPerm {
				if current == path {
					// Exact match — propagate flag irrelevant.
					return true
				}
				// Ancestor match — only effective when propagate=1.
				if privs[priv] != 0 {
					return true
				}
			}
		}

		if current == "/" {
			break
		}

		// Walk to parent.
		idx := strings.LastIndex(current, "/")
		if idx <= 0 {
			current = "/"
		} else {
			current = current[:idx]
		}
	}

	return false
}

// CreateUserRequest carries the parameters for POST /access/users.
type CreateUserRequest struct {
	// UserID is the full PVE userid, e.g. "vault-myrole-a1b2c3d4@pve".
	UserID string
	// Groups is the pve-groupid-list: a SINGLE comma-separated field.
	// Never pass as repeated form keys (PVE mishandles that).
	Groups string
	// Expire is the Unix epoch at which the user account expires.
	// Must be non-zero (the engine refuses unlimited TTLs; see Locked Decision).
	Expire int64
	// Enable should always be true for freshly created lease users.
	Enable bool
	// Comment is an optional free-text annotation written to PVE's user comment
	// field. The issuance path writes the per-attempt WAL nonce here so that
	// walRollbackUser can verify ownership before deleting (prevents deleting a
	// foreign user that coincidentally holds the same userid).
	Comment string
}

// UpdateUserRequest carries the parameters for PUT /access/users/{userid}.
//
// PUT /access/users is a FULL-REPLACE operation (confirmed PVE 9.2.10,
// PVE_PROBES.md Probe 7): an expire-only PUT wipes the groups array and
// strips the credential's privileges. Always re-send Groups+Enable+Append=true.
type UpdateUserRequest struct {
	// UserID identifies the user to update.
	UserID string
	// Expire is the new Unix epoch expiry.
	Expire int64
	// Groups must be re-sent verbatim on every renewal or membership is wiped.
	// Read from lease InternalData, NOT re-derived from the role.
	Groups string
	// Enable should always be true (send enable=1).
	Enable bool
	// Append must be true (send append=1); omitting it defaults to append=0
	// which replaces rather than merges existing attributes.
	Append bool
}

// Validate rejects unsafe UpdateUserRequest combinations before any HTTP
// request can be constructed. Renewal must always preserve the finite PVE
// expire backstop, group membership, enabled state, and append=1 semantics;
// unsafe zero values remove one of those protections.
func (r UpdateUserRequest) Validate() error {
	if r.Expire <= 0 {
		return fmt.Errorf("pveapi: UpdateUserRequest for %q is unsafe: expire=%d would remove the lease expiry backstop", r.UserID, r.Expire)
	}
	if strings.TrimSpace(r.Groups) == "" {
		return fmt.Errorf("pveapi: UpdateUserRequest for %q is unsafe: groups is empty and would wipe group membership", r.UserID)
	}
	if !r.Enable {
		return fmt.Errorf("pveapi: UpdateUserRequest for %q is unsafe: enable=false would disable the lease user", r.UserID)
	}
	if !r.Append {
		return fmt.Errorf("pveapi: UpdateUserRequest for %q is unsafe: append=false would replace user attributes and may wipe groups", r.UserID)
	}
	return nil
}

// UserInfo is the response shape for GET /access/users/{userid}.
// Used for read-back assertions after CreateUser and UpdateUser.
type UserInfo struct {
	// Groups lists the PVE group IDs the user belongs to.
	Groups []string
	// Enable reflects the user's enabled status.
	Enable bool
	// Expire is the Unix epoch expiry (0 means no expiry).
	Expire int64
	// Comment is the free-text annotation stored on the user account.
	// The issuance path writes the per-attempt WAL nonce into this field so
	// walRollbackUser can verify ownership (nonce match) before deleting.
	Comment string
}

// versionResponse is the JSON shape of GET /version.
type versionResponse struct {
	Data struct {
		Version string `json:"version"`
	} `json:"data"`
}

// permissionsResponse is the JSON shape of GET /access/permissions.
// PVE wraps responses in {"data": ...}.
type permissionsResponse struct {
	Data PermissionTree `json:"data"`
}

// pveErrorBody is used to decode PVE error responses for classifyPVEError.
// PVE error bodies look like:
//
//	{"data":null,"message":"...","errors":{"field":"..."}}
//
// The message field is the top-level error; the errors object holds
// per-field validation errors. Both must be searched for error strings.
type pveErrorBody struct {
	Message string            `json:"message"`
	Errors  map[string]string `json:"errors"`
}

// userResponse is the JSON shape of GET /access/users/{userid}.
type userResponse struct {
	Data struct {
		Groups  string `json:"groups"` // comma-separated group list
		Enable  int    `json:"enable"`
		Expire  int64  `json:"expire"`
		Comment string `json:"comment"` // free-text annotation; used for WAL nonce ownership check
	} `json:"data"`
}

// tokenCreateResponse is the JSON shape of POST .../token/{tokenid}.
// The token_secret is one-time and never readable after creation.
type tokenCreateResponse struct {
	Data struct {
		Value string `json:"value"` // the actual token secret
	} `json:"data"`
}
