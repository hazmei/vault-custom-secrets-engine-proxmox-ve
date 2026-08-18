// Package pveapi provides a client for the Proxmox VE REST API.
//
// Error handling follows the PVE 9.2.10 error contract: PVE returns HTTP 500
// (and 400 for token conflicts) with a body containing a message string and/or
// an errors object — NOT 404/409 REST semantics. Error classification is
// body-string based, not status-code based (confirmed PVE 9.2.10, PVE_PROBES.md
// Probes 2–6b). Only HTTP 403 is a genuine status to branch on.
package pveapi

import "errors"

// Sentinel errors returned by the PVE client.
// Mapped by BODY STRING, not HTTP status code.
var (
	// ErrNotFound is returned when the PVE response body contains
	// "no such user", "does not exist", or "no such group" (all HTTP 500).
	// PVE never returns 404 for these conditions.
	ErrNotFound = errors.New("pveapi: not found")

	// ErrConflict is returned when the PVE response body contains
	// "already exists" (user create, HTTP 500) or "Token already exists"
	// (token create, HTTP 400 with the string in errors.tokenid — NOT message).
	ErrConflict = errors.New("pveapi: conflict")

	// ErrForbidden is returned on HTTP 403 (this IS a genuine status code
	// in the PVE API — permission denied is always 403, never 500+body).
	ErrForbidden = errors.New("pveapi: forbidden")
)
