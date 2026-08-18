// Package pveapi provides a client for the Proxmox VE REST API.
//
// Error handling follows the PVE 9.2.10 error contract: PVE returns HTTP 500
// (and 400 for token conflicts) with a body containing a message string and/or
// an errors object — NOT 404/409 REST semantics. Error classification is
// body-string based, not status-code based (confirmed PVE 9.2.10, PVE_PROBES.md
// Probes 2–6b). Only HTTP 403 is a genuine status to branch on.
//
// DR-2: ErrNotFound was split into ErrUserNotFound and ErrGroupNotFound so
// that call sites can distinguish between a missing user (revocation idempotency
// treats it as success; renewal treats it as hard failure) and a missing group
// (role-write surfaces it as "group does not exist"). Using errors.Is avoids a
// second body-string scan at the call site.
package pveapi

import "errors"

// Sentinel errors returned by the PVE client.
// Mapped by BODY STRING, not HTTP status code (confirmed PVE 9.2.10).
var (
	// ErrUserNotFound is returned when the PVE response body contains
	// "no such user" (HTTP 500, e.g. GET/DELETE /access/users/{userid}).
	// PVE never returns 404 for this condition.
	//
	// Revocation keyed on errors.Is(err, ErrUserNotFound) → treat as success
	// (idempotent). Renewal keyed on same → hard failure.
	ErrUserNotFound = errors.New("pveapi: user not found")

	// ErrGroupNotFound is returned when the PVE response body contains
	// "does not exist" (HTTP 500, e.g. GET /access/groups/{group}) or
	// "no such group" (HTTP 500, e.g. POST /access/users with a bad group id).
	// PVE never returns 404 for these conditions.
	//
	// Role-write keyed on errors.Is(err, ErrGroupNotFound) → surface as
	// "group <name> does not exist on Proxmox cluster".
	ErrGroupNotFound = errors.New("pveapi: group not found")

	// ErrConflict is returned when the PVE response body contains
	// "already exists" (user create, HTTP 500) or "Token already exists"
	// (token create, HTTP 400 with the string in errors.tokenid — NOT message).
	ErrConflict = errors.New("pveapi: conflict")

	// ErrForbidden is returned on HTTP 403 (this IS a genuine status code
	// in the PVE API — permission denied is always 403, never 500+body).
	ErrForbidden = errors.New("pveapi: forbidden")
)
