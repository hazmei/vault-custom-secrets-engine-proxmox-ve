// Package proxmox — password generation for password-mode dynamic credentials.
//
// Contract locked in docs/IMPLEMENTATION_PLAN.md P1, from the verified
// pve-manager/9.2.14/a1480fa6b8d899cb evidence in docs/PVE_PROBES.md Probe P0.
// Raw-API password probes were also run on 9.2.10 (Probe P0 rerun, 28 August
// 2026), but password mode was not exercised end to end through the engine on
// that build and remains unsupported there:
//
//   - Ownership: the ENGINE generates the password. PVE never generates one,
//     and PUT /access/password (PVE-side rotation) requires a password-
//     authenticated ticket the engine cannot obtain with API-token auth.
//   - Entropy source: crypto/rand only, with rejection sampling (no modulo bias).
//   - Length: passwordLength characters, inside the verified PVE 8..64 bound.
//   - Charset: ASCII alphanumerics. Deliberately excludes punctuation so the
//     value is safe to paste into shells, URLs, and config files without
//     quoting; the entropy budget below already covers the loss.
//
// The generated value is a live credential the moment CreateUser succeeds. It
// is returned to the caller exactly once and is never written to logs, errors,
// the WAL, Secret.InternalData, or backend-controlled storage.
package proxmox

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

const (
	// passwordCharset is the ASCII alphanumeric alphabet (62 symbols).
	passwordCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	// passwordLength is the generated password length in characters.
	// 32 × log2(62) ≈ 190 bits of entropy, well inside PVE's 8..64 limit
	// (28 August 2026 raw-API rerun on pve-manager/9.2.10: 7 rejected, 8
	// accepted, 64 accepted, 65 rejected).
	passwordLength = 32

	// pvePasswordMinLength and pvePasswordMaxLength are PVE's confirmed
	// constraints. They exist so a future change to passwordLength cannot
	// silently drift outside what PVE accepts.
	pvePasswordMinLength = 8
	pvePasswordMaxLength = 64
)

// generatePassword returns a fresh random password.
//
// Uses crypto/rand.Int for uniform selection over the charset (rejection
// sampling is handled inside rand.Int), so there is no modulo bias.
//
// The error is deliberately free of any generated material.
func generatePassword() (string, error) {
	if passwordLength < pvePasswordMinLength || passwordLength > pvePasswordMaxLength {
		return "", fmt.Errorf("proxmox: passwordLength %d is outside the PVE-accepted range %d..%d",
			passwordLength, pvePasswordMinLength, pvePasswordMaxLength)
	}

	max := big.NewInt(int64(len(passwordCharset)))
	buf := make([]byte, passwordLength)
	for i := range buf {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", fmt.Errorf("proxmox: generate password: %w", err)
		}
		buf[i] = passwordCharset[n.Int64()]
	}
	return string(buf), nil
}
