// Package proxmox — userid assembly, validation, and random suffix generation.
//
// Proxmox userids have the format:
//
//	<user>@<realm>
//
// where <user> is [^\s:/]+ (any chars except whitespace, ':', '/') and <realm>
// must match ^[A-Za-z][A-Za-z0-9.\-_]+$. Additionally, '@' and '!' are
// forbidden in user_prefix and role name because they break the
// PVEAPIToken Authorization header grammar:
//
//	Authorization: PVEAPIToken=<user>@<realm>!<tokenid>=<secret>
//
// The synthetic userid format produced by this engine is:
//
//	{user_prefix}-{role}-{random}@{realm}
//
// Confirmed PVE 9.2.10 (commit cf651ab): the full userid including @realm must
// be <= 64 characters. POST /access/users returns HTTP 400 with format error
// "user name '<name>@<realm>' is too long (N > 64)" otherwise.
package proxmox

import (
	"crypto/rand"
	"fmt"
)

// crockfordBase32 is the lowercase Crockford base32 alphabet (no padding, no
// ambiguous characters).
// See https://www.crockford.com/base32.html
const crockfordBase32 = "0123456789abcdefghjkmnpqrstvwxyz"

// randomSuffix generates an 8-character lowercase Crockford base32 random
// string (~40 bits of entropy). Used as the per-lease random component of the
// synthetic userid.
//
// 5 bits per character × 8 characters = 40 bits entropy. Collision probability
// is negligible at typical issuance rates.
func randomSuffix() (string, error) {
	// We need 8 characters from a 32-symbol alphabet (5 bits each = 40 bits total).
	// Read 5 random bytes (40 bits) and convert each 5-bit group to an index.
	b := make([]byte, 5)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("proxmox: generate random suffix: %w", err)
	}

	// Pack 5 bytes into a 40-bit integer, then extract 8 × 5-bit groups.
	var val uint64
	for _, byt := range b {
		val = (val << 8) | uint64(byt)
	}

	buf := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		buf[i] = crockfordBase32[val&0x1F]
		val >>= 5
	}
	return string(buf), nil
}

// buildUserID assembles the synthetic Proxmox userid from its components.
//
// Format: {prefix}-{role}-{suffix}@{realm}
//
// The caller is responsible for validating individual components with
// validateUserComponent and validateLengthBudget before calling buildUserID.
func buildUserID(userPrefix, role, randomSuffix, realm string) string {
	return userPrefix + "-" + role + "-" + randomSuffix + "@" + realm
}

// validateUserComponent validates a user_prefix or role name against the
// Proxmox userid character set.
//
// A component is rejected if it is:
//   - empty
//   - contains whitespace (breaks `[^\s:/]+` PVE username regex)
//   - contains ':' or '/' (reserved by PVE username regex)
//   - contains '@' or '!' (break PVEAPIToken Authorization header grammar)
//
// See docs/ARCHITECTURE.md — Roles section, userid character set.
func validateUserComponent(s string) error {
	if s == "" {
		return fmt.Errorf("proxmox: user component must not be empty")
	}
	for _, r := range s {
		switch {
		case r == ':':
			return fmt.Errorf("proxmox: user component %q contains forbidden character ':'", s)
		case r == '/':
			return fmt.Errorf("proxmox: user component %q contains forbidden character '/'", s)
		case r == '@':
			return fmt.Errorf("proxmox: user component %q contains forbidden character '@' (breaks PVEAPIToken header grammar)", s)
		case r == '!':
			return fmt.Errorf("proxmox: user component %q contains forbidden character '!' (breaks PVEAPIToken header grammar)", s)
		case isWhitespace(r):
			return fmt.Errorf("proxmox: user component %q contains whitespace", s)
		}
	}
	return nil
}

// isWhitespace reports whether r is an ASCII whitespace character.
func isWhitespace(r rune) bool {
	return r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '\f' || r == '\v'
}

// validateRealmComponent validates a realm value against the PVE realm regex
// ^[A-Za-z][A-Za-z0-9.\-_]+$.
//
// Realm must start with a letter, followed by at least one letter, digit, dot,
// hyphen, or underscore. An empty realm is rejected (callers should default it
// to "pve" first).
func validateRealmComponent(realm string) error {
	if realm == "" {
		return fmt.Errorf("proxmox: realm must not be empty")
	}
	if len(realm) < 2 {
		return fmt.Errorf("proxmox: realm %q is too short (minimum 2 characters)", realm)
	}
	first := rune(realm[0])
	if !isASCIILetter(first) {
		return fmt.Errorf("proxmox: realm %q must start with a letter (A-Z or a-z)", realm)
	}
	for _, r := range realm[1:] {
		if !isASCIILetter(r) && !isASCIIDigit(r) && r != '.' && r != '-' && r != '_' {
			return fmt.Errorf("proxmox: realm %q contains invalid character %q (allowed: A-Za-z0-9.-_)", realm, string(r))
		}
	}
	return nil
}

// validateLengthBudget ensures the assembled userid will not exceed the PVE
// 64-character limit (confirmed PVE 9.2.10, commit cf651ab).
//
// Budget:  len(prefix) + 1 + len(role) + 1 + 8 + 1 + len(realm)
//           prefix        -    role       -   random  @   realm
// Must be <= 64.
//
// Call AFTER realm defaulting (so the effective realm length is used) but
// BEFORE making a PVE API call (rejects at write time, not at issuance time).
func validateLengthBudget(userPrefix, role, realm string) error {
	// fixed overhead: 1('-') + 1('-') + 8(random) + 1('@') = 11
	total := len(userPrefix) + 1 + len(role) + 1 + 8 + 1 + len(realm)
	if total > 64 {
		return fmt.Errorf(
			"proxmox: userid would be %d characters (> 64); shorten user_prefix (%d), role name (%d), or realm (%d chars each): budget = len(prefix)+1+len(role)+1+8+1+len(realm) <= 64",
			total, len(userPrefix), len(role), len(realm),
		)
	}
	return nil
}

// isASCIILetter reports whether r is an ASCII letter (A-Z or a-z).
func isASCIILetter(r rune) bool {
	return (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z')
}

// isASCIIDigit reports whether r is an ASCII digit (0-9).
func isASCIIDigit(r rune) bool {
	return r >= '0' && r <= '9'
}
