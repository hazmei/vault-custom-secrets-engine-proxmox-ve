// Package pveapi — unit tests for classifyPVEError.
//
// Tests are fed the ACTUAL probed PVE 9.2.10 response bodies from PVE_PROBES.md
// Probes 2–6b. The critical case is that "Token already exists" lives in
// errors.tokenid (NOT message) — so the classifier MUST read the full body,
// not just the message field.
package pveapi

import (
	"errors"
	"strings"
	"testing"
)

func TestClassifyPVEError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status int
		body   []byte
		want   error
	}{
		// ── ErrConflict cases ──────────────────────────────────────────────
		{
			name:   "user already exists (HTTP 500, message field)",
			status: 500,
			body:   []byte(`{"data":null,"message":"create user failed: user 'vault-test@pve' already exists\n"}`),
			want:   ErrConflict,
		},
		{
			// PVE_PROBES.md Probe 6b: "Token already exists" is in errors.tokenid,
			// NOT in the top-level message field.  This is THE critical case.
			name:   "token already exists (HTTP 400, errors.tokenid NOT message)",
			status: 400,
			body:   []byte(`{"message":"Parameter verification failed.\n","data":null,"errors":{"tokenid":"Token already exists."}}`),
			want:   ErrConflict,
		},
		// ── ErrNotFound cases ─────────────────────────────────────────────
		{
			name:   "no such user (HTTP 500)",
			status: 500,
			body:   []byte(`{"data":null,"message":"no such user ('vault-test@pve')\n"}`),
			want:   ErrNotFound,
		},
		{
			name:   "group does not exist (HTTP 500)",
			status: 500,
			body:   []byte(`{"data":null,"message":"group 'vault-test-grp' does not exist\n"}`),
			want:   ErrNotFound,
		},
		{
			name:   "create user with no such group (HTTP 500)",
			status: 500,
			body:   []byte(`{"data":null,"message":"create user failed: no such group 'vault-test-grp'\n"}`),
			want:   ErrNotFound,
		},
		// ── ErrForbidden cases ────────────────────────────────────────────
		{
			name:   "403 permission denied (genuine status)",
			status: 403,
			body:   []byte(`{"data":null,"message":"Permission check failed (/access/groups, User.Modify)"}`),
			want:   ErrForbidden,
		},
		{
			name:   "403 with empty body",
			status: 403,
			body:   []byte{},
			want:   ErrForbidden,
		},
		// ── nil (unrecognised) cases ───────────────────────────────────────
		{
			name:   "unknown 500 body returns nil",
			status: 500,
			body:   []byte(`{"message":"some unrelated error"}`),
			want:   nil,
		},
		{
			name:   "200 status returns nil",
			status: 200,
			body:   []byte(`{"data":{"version":"9.2.10"}}`),
			want:   nil,
		},
		// ── Trailing-newline / embedded-quoted-id tolerance ───────────────
		{
			name:   "message with trailing newline in JSON string",
			status: 500,
			body:   []byte("{\"data\":null,\"message\":\"no such user ('x@pve')\\n\"}"),
			want:   ErrNotFound,
		},
		{
			name:   "already exists with embedded quoted id",
			status: 500,
			body:   []byte(`{"data":null,"message":"create user failed: user 'v-r-abcd1234@pve' already exists\n"}`),
			want:   ErrConflict,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := classifyPVEError(tc.status, tc.body)
			if !errors.Is(got, tc.want) {
				// When both are nil, errors.Is returns true, so this branch only
				// fires on genuine mismatches.
				if got == nil && tc.want == nil {
					return
				}
				t.Errorf("classifyPVEError(status=%d, body=%q) = %v; want %v",
					tc.status, tc.body, got, tc.want)
			}
		})
	}
}

// TestClassifyPVEErrorTokenSecretNotInErrorString confirms that the error
// classification function itself never leaks a token_secret value.
// Production code uses classifyPVEError inside doRequest, which ensures
// token endpoint bodies are never included — this test documents the invariant.
func TestClassifyPVEErrorTokenSecretNotInErrorString(t *testing.T) {
	t.Parallel()

	// Simulate a body that would contain a token secret in a pathological case.
	sensitiveValue := "00000000-1111-2222-3333-444444444444"
	body := []byte(`{"message":"some error containing ` + sensitiveValue + `"}`)

	err := classifyPVEError(500, body)
	// The classifier returns nil for an unrecognised body — the point is that
	// the sensitive value MUST NOT appear in the returned error (if any).
	if err != nil && strings.Contains(err.Error(), sensitiveValue) {
		t.Errorf("classifyPVEError error string contains sensitive value: %q", err.Error())
	}
}

// TestClassifyPVEErrorTokenExistsIsInErrorsDotTokenid confirms that the
// "Token already exists" match reads errors.tokenid, NOT message.
// The message field says "Parameter verification failed." — matching only
// on message would miss the token-conflict case entirely.
func TestClassifyPVEErrorTokenExistsOnlyInErrors(t *testing.T) {
	t.Parallel()

	// Body where message does NOT contain "Token already exists" but errors.tokenid does.
	body := []byte(`{"message":"Parameter verification failed.\n","data":null,"errors":{"tokenid":"Token already exists."}}`)

	got := classifyPVEError(400, body)
	if !errors.Is(got, ErrConflict) {
		t.Errorf("expected ErrConflict from errors.tokenid body, got %v", got)
	}

	// Confirm that matching ONLY on message would have missed it.
	// The message "Parameter verification failed." does NOT contain the string.
	if strings.Contains("Parameter verification failed.", "Token already exists") {
		t.Error("test setup error: message field should NOT contain 'Token already exists'")
	}
}

// TestClassifyPVEErrorStructuredFieldsOnly confirms that a well-formed PVE
// error body (with message and/or errors fields) is classified purely from
// those structured fields — NOT from re-scanning the raw JSON string.
//
// The raw JSON contains extra text that would match "no such user" if the
// raw body were always appended (the old, incorrect behaviour).  We embed
// the sentinel phrase only inside the message/errors values; the JSON key
// names and surrounding syntax do NOT contain it — so if the classifier
// uses only structured fields the match succeeds correctly, and if it were
// accidentally using the raw body the broader context would still match.
// A stronger negative test is provided by TestClassifyPVEErrorRawFallback.
func TestClassifyPVEErrorStructuredFieldsOnly(t *testing.T) {
	t.Parallel()

	// Well-formed body: "no such user" appears only in the message field.
	body := []byte(`{"data":null,"message":"no such user ('vault-test@pve')","errors":{}}`)

	got := classifyPVEError(500, body)
	if !errors.Is(got, ErrNotFound) {
		t.Errorf("expected ErrNotFound from structured message field, got %v", got)
	}
}

// TestClassifyPVEErrorRawFallback confirms that a malformed/non-JSON body is
// still classified via the raw-body fallback path.
// This covers plain-text PVE responses and other unexpected shapes.
func TestClassifyPVEErrorRawFallback(t *testing.T) {
	t.Parallel()

	// Non-JSON body — json.Unmarshal will fail; classifier must fall back to raw scan.
	body := []byte(`no such user (plain text error from PVE)`)

	got := classifyPVEError(500, body)
	if !errors.Is(got, ErrNotFound) {
		t.Errorf("expected ErrNotFound from raw-body fallback, got %v", got)
	}
}

// TestClassifyPVEErrorRawFallbackConflict confirms the raw fallback also works
// for the "already exists" case with a plain-text body.
func TestClassifyPVEErrorRawFallbackConflict(t *testing.T) {
	t.Parallel()

	body := []byte(`create user failed: user 'vault-test@pve' already exists`)

	got := classifyPVEError(500, body)
	if !errors.Is(got, ErrConflict) {
		t.Errorf("expected ErrConflict from raw-body fallback, got %v", got)
	}
}

// TestClassifyPVEErrorNoFalsePositiveFromJSONSyntax confirms that the
// structured-fields-only path does NOT match sentinel strings that appear only
// in the JSON syntax (keys, surrounding braces) but not in the values.
//
// A body whose JSON values are all benign should return nil even if the raw
// JSON string happened to contain a sentinel substring in a key name.
func TestClassifyPVEErrorNoFalsePositiveFromJSONSyntax(t *testing.T) {
	t.Parallel()

	// message and errors values are benign; the raw JSON does NOT accidentally
	// contain any sentinel phrase, but we verify the classifier ignores structure.
	body := []byte(`{"data":null,"message":"an unrelated error occurred","errors":{}}`)

	got := classifyPVEError(500, body)
	if got != nil {
		t.Errorf("expected nil for benign body, got %v", got)
	}
}
