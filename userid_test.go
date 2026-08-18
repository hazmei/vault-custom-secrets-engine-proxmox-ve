// Package proxmox — unit tests for userid.go.
//
// Covers:
//   - buildUserID: correct format assembly.
//   - randomSuffix: 8-character output, valid Crockford base32 alphabet, entropy
//     (no two consecutive calls return the same suffix in the vast majority of runs).
//   - validateUserComponent: accepts valid strings, rejects empty, whitespace, ':', '/', '@', '!'.
//   - validateRealmComponent: accepts valid realms, rejects invalid ones.
//   - validateLengthBudget: accepts exactly 64 chars, rejects 65+ chars.
package proxmox

import (
	"strings"
	"testing"
)

// ── buildUserID ────────────────────────────────────────────────────────────────

func TestBuildUserID_Format(t *testing.T) {
	t.Parallel()

	got := buildUserID("vault", "myrole", "ab12cd34", "pve")
	want := "vault-myrole-ab12cd34@pve"
	if got != want {
		t.Errorf("buildUserID = %q; want %q", got, want)
	}
}

func TestBuildUserID_LongerComponents(t *testing.T) {
	t.Parallel()

	got := buildUserID("myprefix", "long-role-name", "abcdefgh", "realm1")
	want := "myprefix-long-role-name-abcdefgh@realm1"
	if got != want {
		t.Errorf("buildUserID = %q; want %q", got, want)
	}
}

func TestBuildUserID_ContainsAtSign(t *testing.T) {
	t.Parallel()

	got := buildUserID("v", "r", "00000000", "pve")
	if !strings.Contains(got, "@") {
		t.Errorf("buildUserID output must contain '@'; got %q", got)
	}
}

func TestBuildUserID_PartsSeparatedByHyphen(t *testing.T) {
	t.Parallel()

	got := buildUserID("p", "r", "s", "realm")
	// Expected: "p-r-s@realm"
	parts := strings.SplitN(got, "@", 2)
	if len(parts) != 2 {
		t.Fatalf("expected '@' separator; got %q", got)
	}
	userPart := parts[0]   // "p-r-s"
	realmPart := parts[1]  // "realm"

	if realmPart != "realm" {
		t.Errorf("realm part = %q; want %q", realmPart, "realm")
	}

	subparts := strings.Split(userPart, "-")
	if len(subparts) != 3 {
		t.Errorf("expected 3 hyphen-separated parts in user portion; got %v (from %q)", subparts, userPart)
	}
	if subparts[0] != "p" || subparts[1] != "r" || subparts[2] != "s" {
		t.Errorf("user parts = %v; want [p r s]", subparts)
	}
}

// ── randomSuffix ──────────────────────────────────────────────────────────────

func TestRandomSuffix_Length(t *testing.T) {
	t.Parallel()

	s, err := randomSuffix()
	if err != nil {
		t.Fatalf("randomSuffix: %v", err)
	}
	if len(s) != 8 {
		t.Errorf("randomSuffix length = %d; want 8", len(s))
	}
}

func TestRandomSuffix_OnlyCrockfordAlphabet(t *testing.T) {
	t.Parallel()

	// Run many iterations to get good coverage of the alphabet.
	for i := 0; i < 50; i++ {
		s, err := randomSuffix()
		if err != nil {
			t.Fatalf("randomSuffix iteration %d: %v", i, err)
		}
		for j, c := range s {
			if !strings.ContainsRune(crockfordBase32, c) {
				t.Errorf("randomSuffix %q: character %q at position %d is not in Crockford alphabet", s, string(c), j)
			}
		}
	}
}

func TestRandomSuffix_Entropy(t *testing.T) {
	t.Parallel()

	// Generate 20 suffixes — the probability of any two being equal is
	// (1/32^8)^(20 choose 2) ≈ 10^{-59}. If we see even one duplicate,
	// the CSPRNG is broken.
	seen := make(map[string]bool)
	for i := 0; i < 20; i++ {
		s, err := randomSuffix()
		if err != nil {
			t.Fatalf("randomSuffix iteration %d: %v", i, err)
		}
		if seen[s] {
			t.Errorf("randomSuffix produced duplicate %q (CSPRNG entropy problem)", s)
		}
		seen[s] = true
	}
}

func TestRandomSuffix_NoUppercase(t *testing.T) {
	t.Parallel()

	for i := 0; i < 20; i++ {
		s, err := randomSuffix()
		if err != nil {
			t.Fatalf("randomSuffix: %v", err)
		}
		if s != strings.ToLower(s) {
			t.Errorf("randomSuffix %q contains uppercase characters", s)
		}
	}
}

// ── validateUserComponent ─────────────────────────────────────────────────────

func TestValidateUserComponent_ValidStrings(t *testing.T) {
	t.Parallel()

	valids := []string{
		"vault",
		"myrole",
		"my-role",
		"my_role",
		"my.role",
		"role123",
		"123",
		"a",
	}
	for _, s := range valids {
		s := s
		t.Run(s, func(t *testing.T) {
			t.Parallel()
			if err := validateUserComponent(s); err != nil {
				t.Errorf("validateUserComponent(%q) returned unexpected error: %v", s, err)
			}
		})
	}
}

func TestValidateUserComponent_RejectsEmpty(t *testing.T) {
	t.Parallel()

	if err := validateUserComponent(""); err == nil {
		t.Error("validateUserComponent(\"\") should return an error for empty string")
	}
}

func TestValidateUserComponent_RejectsColon(t *testing.T) {
	t.Parallel()

	if err := validateUserComponent("vault:admin"); err == nil {
		t.Error("validateUserComponent(\"vault:admin\") should return an error (colon forbidden)")
	}
}

func TestValidateUserComponent_RejectsSlash(t *testing.T) {
	t.Parallel()

	if err := validateUserComponent("vault/role"); err == nil {
		t.Error("validateUserComponent(\"vault/role\") should return an error (slash forbidden)")
	}
}

func TestValidateUserComponent_RejectsAtSign(t *testing.T) {
	t.Parallel()

	if err := validateUserComponent("vault@pve"); err == nil {
		t.Error("validateUserComponent(\"vault@pve\") should return an error (@ forbidden)")
	}
}

func TestValidateUserComponent_RejectsBang(t *testing.T) {
	t.Parallel()

	if err := validateUserComponent("vault!token"); err == nil {
		t.Error("validateUserComponent(\"vault!token\") should return an error (! forbidden)")
	}
}

func TestValidateUserComponent_RejectsSpace(t *testing.T) {
	t.Parallel()

	if err := validateUserComponent("vault role"); err == nil {
		t.Error("validateUserComponent(\"vault role\") should return an error (space forbidden)")
	}
}

func TestValidateUserComponent_RejectsTab(t *testing.T) {
	t.Parallel()

	if err := validateUserComponent("vault\trole"); err == nil {
		t.Error("validateUserComponent(\"vault\\trole\") should return an error (tab forbidden)")
	}
}

func TestValidateUserComponent_RejectsNewline(t *testing.T) {
	t.Parallel()

	if err := validateUserComponent("vault\nrole"); err == nil {
		t.Error("validateUserComponent(\"vault\\nrole\") should return an error (newline forbidden)")
	}
}

// ── validateRealmComponent ────────────────────────────────────────────────────

func TestValidateRealmComponent_ValidRealms(t *testing.T) {
	t.Parallel()

	valids := []string{
		"pve",
		"pam",
		"ldap",
		"Realm1",
		"my-realm",
		"my_realm",
		"my.realm",
	}
	for _, s := range valids {
		s := s
		t.Run(s, func(t *testing.T) {
			t.Parallel()
			if err := validateRealmComponent(s); err != nil {
				t.Errorf("validateRealmComponent(%q) returned unexpected error: %v", s, err)
			}
		})
	}
}

func TestValidateRealmComponent_RejectsEmpty(t *testing.T) {
	t.Parallel()

	if err := validateRealmComponent(""); err == nil {
		t.Error("validateRealmComponent(\"\") should return an error")
	}
}

func TestValidateRealmComponent_RejectsSingleChar(t *testing.T) {
	t.Parallel()

	if err := validateRealmComponent("p"); err == nil {
		t.Error("validateRealmComponent(\"p\") should return an error (too short)")
	}
}

func TestValidateRealmComponent_RejectsStartingWithDigit(t *testing.T) {
	t.Parallel()

	if err := validateRealmComponent("1pve"); err == nil {
		t.Error("validateRealmComponent(\"1pve\") should return an error (must start with letter)")
	}
}

func TestValidateRealmComponent_RejectsInvalidChar(t *testing.T) {
	t.Parallel()

	if err := validateRealmComponent("pve@realm"); err == nil {
		t.Error("validateRealmComponent(\"pve@realm\") should return an error (@ forbidden)")
	}
}

// ── validateLengthBudget ──────────────────────────────────────────────────────

// TestValidateLengthBudget_Exactly64Accepted verifies that a userid assembling
// to exactly 64 characters passes the budget check.
//
// Formula: len(prefix) + 1 + len(role) + 1 + 8 + 1 + len(realm) = 64
// With realm = "pve" (3 chars), overhead = 8 + 1 + 1 + 1 + 3 = 14.
// Remaining budget for prefix+role = 64 - 14 = 50.
// Split: prefix = 25 chars, role = 25 chars → total = 25+1+25+1+8+1+3 = 64. ✓
func TestValidateLengthBudget_Exactly64Accepted(t *testing.T) {
	t.Parallel()

	prefix := strings.Repeat("a", 25) // 25 chars
	role := strings.Repeat("b", 25)   // 25 chars
	realm := "pve"                    // 3 chars
	// total = 25+1+25+1+8+1+3 = 64 ✓

	if err := validateLengthBudget(prefix, role, realm); err != nil {
		t.Errorf("expected no error for exactly-64 budget; got: %v", err)
	}
}

// TestValidateLengthBudget_65Rejected verifies that a userid assembling
// to 65 characters is rejected.
//
// prefix = 26, role = 25, realm = "pve" → 26+1+25+1+8+1+3 = 65.
func TestValidateLengthBudget_65Rejected(t *testing.T) {
	t.Parallel()

	prefix := strings.Repeat("a", 26) // 26 chars
	role := strings.Repeat("b", 25)   // 25 chars
	realm := "pve"                    // 3 chars
	// total = 26+1+25+1+8+1+3 = 65 ✗

	if err := validateLengthBudget(prefix, role, realm); err == nil {
		t.Error("expected error for 65-character budget; got nil")
	}
}

// TestValidateLengthBudget_ShortInputsAccepted verifies typical short inputs pass.
func TestValidateLengthBudget_ShortInputsAccepted(t *testing.T) {
	t.Parallel()

	if err := validateLengthBudget("vault", "myrole", "pve"); err != nil {
		t.Errorf("unexpected error for short inputs: %v", err)
	}
}

// TestValidateLengthBudget_LongRealmReducesBudget verifies that a longer realm
// reduces the budget for prefix+role.
func TestValidateLengthBudget_LongRealmReducesBudget(t *testing.T) {
	t.Parallel()

	// realm = 20 chars → overhead = 8+1+1+1+20 = 31 → budget for prefix+role = 33.
	// prefix = 20, role = 14 → total = 20+1+14+1+8+1+20 = 65 → should fail.
	longRealm := strings.Repeat("r", 19) + "m" // 20 chars, valid (starts with letter)
	prefix := strings.Repeat("a", 20)
	role := strings.Repeat("b", 14)
	// total = 20+1+14+1+8+1+20 = 65 ✗

	if err := validateLengthBudget(prefix, role, longRealm); err == nil {
		t.Error("expected error when long realm causes total to exceed 64; got nil")
	}
}

// TestValidateLengthBudget_63Accepted verifies budget of 63 is fine.
func TestValidateLengthBudget_63Accepted(t *testing.T) {
	t.Parallel()

	prefix := strings.Repeat("a", 24) // 24 chars
	role := strings.Repeat("b", 25)   // 25 chars
	realm := "pve"                    // 3 chars
	// total = 24+1+25+1+8+1+3 = 63 ✓

	if err := validateLengthBudget(prefix, role, realm); err != nil {
		t.Errorf("expected no error for 63-char budget; got: %v", err)
	}
}

// ── crockfordBase32 alphabet invariant ────────────────────────────────────────

// TestCrockfordBase32Alphabet verifies that the Crockford base32 alphabet
// constant has exactly 32 symbols and all symbols are unique.
//
// This was previously enforced by an init()-time panic; moved to a unit test
// so the invariant is validated by the test suite rather than at program start.
func TestCrockfordBase32Alphabet(t *testing.T) {
	t.Parallel()

	if len(crockfordBase32) != 32 {
		t.Errorf("crockfordBase32 must have exactly 32 symbols; got %d", len(crockfordBase32))
	}

	seen := make(map[rune]bool, 32)
	for i, c := range crockfordBase32 {
		if seen[c] {
			t.Errorf("crockfordBase32 has duplicate character %q at index %d", string(c), i)
		}
		seen[c] = true
	}
}
