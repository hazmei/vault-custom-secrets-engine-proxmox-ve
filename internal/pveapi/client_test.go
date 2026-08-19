// Package pveapi — httptest-based wire encoding tests for the real HTTP client.
//
// These tests assert that the real client serializes form fields with the
// exact literal values that PVE requires:
//   - privsep=0  (literal "0", never omitted — privsep=1 gives empty ACL)
//   - enable=1   (literal "1" on CreateUser)
//   - append=1   (literal "1" on UpdateUser/renewal)
//   - groups     as ONE comma-separated field, never array-repeated
//
// Also asserts that the Authorization header is in PVEAPIToken format,
// and that token_secret never appears in error strings from the client.
package pveapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// makeTestClient creates a real httpClient pointed at the given TLS test server.
// It sets TLSSkipVerify=true since httptest.NewTLSServer uses a self-signed cert.
func makeTestClient(t *testing.T, serverURL, tokenID, tokenSecret string) Client {
	t.Helper()
	client, err := NewClient(ClientConfig{
		Address:       serverURL,
		TokenID:       tokenID,
		TokenSecret:   tokenSecret,
		TLSSkipVerify: true, // httptest TLS server uses a self-signed cert
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client
}

// TestClientAuthHeaderFormat asserts the Authorization header is sent in
// the correct PVEAPIToken format on every request.
func TestClientAuthHeaderFormat(t *testing.T) {
	t.Parallel()

	const tokenID = "vault-admin@pve!mytoken"
	const tokenSecret = "test-secret-uuid"
	wantHeader := "PVEAPIToken=" + tokenID + "=" + tokenSecret

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("Authorization")
		if got != wantHeader {
			t.Errorf("Authorization header = %q; want %q", got, wantHeader)
		}
		// Respond with a minimal valid version response.
		_ = json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck // httptest handler — write error not actionable
			"data": map[string]interface{}{"version": "9.2.10"},
		})
	}))
	defer ts.Close()

	client := makeTestClient(t, ts.URL, tokenID, tokenSecret)
	if _, err := client.GetVersion(context.Background()); err != nil {
		t.Fatalf("GetVersion: %v", err)
	}
}

// TestGetPermissionsParsesTree asserts that GetPermissions correctly parses
// the PVE permissions tree response and returns a PermissionTree.
func TestGetPermissionsParsesTree(t *testing.T) {
	t.Parallel()

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api2/json/access/permissions" {
			t.Errorf("unexpected path: %q", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck // httptest handler — write error not actionable
			"data": map[string]interface{}{
				"/access/groups": map[string]interface{}{
					"User.Modify": 1,
					"Sys.Audit":   1,
				},
				"/access/realm/pve": map[string]interface{}{
					"Realm.AllocateUser": 1,
				},
			},
		})
	}))
	defer ts.Close()

	client := makeTestClient(t, ts.URL, "admin@pve!tok", "secret")
	tree, err := client.GetPermissions(context.Background())
	if err != nil {
		t.Fatalf("GetPermissions: %v", err)
	}

	if !tree.HasPrivilege("/access/groups", "User.Modify") {
		t.Error("expected User.Modify at /access/groups")
	}
	if !tree.HasPrivilege("/access/groups", "Sys.Audit") {
		t.Error("expected Sys.Audit at /access/groups")
	}
	if !tree.HasPrivilege("/access/realm/pve", "Realm.AllocateUser") {
		t.Error("expected Realm.AllocateUser at /access/realm/pve")
	}
}

// TestCreateTokenPrivsepIsLiteralZero asserts that CreateToken always sends
// privsep as the literal string "0" on the wire.
// This is MANDATORY: PVE defaults privsep=1 when the field is absent or
// "false", giving the token an empty ACL with zero effective permissions.
// privsep is hardcoded in the impl; there is no caller-visible bool parameter.
func TestCreateTokenPrivsepIsLiteralZero(t *testing.T) {
	t.Parallel()

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}

		privsep := r.FormValue("privsep")
		if privsep != "0" {
			t.Errorf("privsep form value = %q; want literal \"0\"", privsep)
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck // httptest handler — write error not actionable
			"data": map[string]interface{}{
				"value": "tok-secret-value",
			},
		})
	}))
	defer ts.Close()

	client := makeTestClient(t, ts.URL, "admin@pve!tok", "secret")
	_, err := client.CreateToken(context.Background(), "vault-test@pve", "vault")
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
}

// TestCreateUserEnableIsLiteralOne asserts that CreateUser sends enable as
// the literal "1" (not bool encoding, not omitted).
func TestCreateUserEnableIsLiteralOne(t *testing.T) {
	t.Parallel()

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		enable := r.FormValue("enable")
		if enable != "1" {
			t.Errorf("enable form value = %q; want literal \"1\"", enable)
		}
		// Return 200 with empty data.
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": nil}) //nolint:errcheck // httptest handler — write error not actionable
	}))
	defer ts.Close()

	client := makeTestClient(t, ts.URL, "admin@pve!tok", "secret")
	err := client.CreateUser(context.Background(), CreateUserRequest{
		UserID: "vault-myrole-abc@pve",
		Groups: "vault-test-grp",
		Expire: 9999999999,
		Enable: true,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
}

// TestCreateUserGroupsIsOneCSVField asserts that CreateUser sends groups as
// a single comma-separated form field, never as array-repeated keys.
func TestCreateUserGroupsIsOneCSVField(t *testing.T) {
	t.Parallel()

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}

		// r.Form["groups"] is a []string — assert exactly one entry.
		groupsValues := r.Form["groups"]
		if len(groupsValues) != 1 {
			t.Errorf("groups field has %d values; want exactly 1 (never array-repeated)", len(groupsValues))
		}
		// The single value should be the CSV string.
		if len(groupsValues) == 1 {
			want := "grp-a,grp-b"
			if groupsValues[0] != want {
				t.Errorf("groups value = %q; want %q", groupsValues[0], want)
			}
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": nil}) //nolint:errcheck // httptest handler — write error not actionable
	}))
	defer ts.Close()

	client := makeTestClient(t, ts.URL, "admin@pve!tok", "secret")
	err := client.CreateUser(context.Background(), CreateUserRequest{
		UserID: "vault-test@pve",
		Groups: "grp-a,grp-b", // two groups as a single CSV field
		Expire: 9999999999,
		Enable: true,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
}

// TestUpdateUserAppendIsLiteralOne asserts that UpdateUser sends append as
// the literal "1" (required on renewal to prevent full-replace wiping groups).
func TestUpdateUserAppendIsLiteralOne(t *testing.T) {
	t.Parallel()

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			return // only check PUT
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}

		appendVal := r.FormValue("append")
		if appendVal != "1" {
			t.Errorf("append form value = %q; want literal \"1\"", appendVal)
		}

		// Also assert groups is one CSV field on UpdateUser.
		groupsValues := r.Form["groups"]
		if len(groupsValues) != 1 {
			t.Errorf("groups on UpdateUser: %d values; want exactly 1", len(groupsValues))
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": nil}) //nolint:errcheck // httptest handler — write error not actionable
	}))
	defer ts.Close()

	client := makeTestClient(t, ts.URL, "admin@pve!tok", "secret")
	err := client.UpdateUser(context.Background(), UpdateUserRequest{
		UserID: "vault-test@pve",
		Expire: 9999999999,
		Groups: "vault-test-grp",
		Enable: true,
		Append: true,
	})
	if err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
}

// TestTokenSecretNeverInErrorStrings asserts that token_secret does not appear
// in error strings returned by the client for failing token-endpoint requests.
// The client redacts the response body for POST .../token/... endpoints.
func TestTokenSecretNeverInErrorStrings(t *testing.T) {
	t.Parallel()

	const tokenSecret = "super-secret-token-value-must-not-leak"

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate a 500 error response that PVE might return.
		// The body contains the word "secret" — should never appear in errors.
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"message":"internal error: ` + tokenSecret + `"}`)) //nolint:errcheck // httptest handler — write error not actionable
	}))
	defer ts.Close()

	client := makeTestClient(t, ts.URL, "admin@pve!tok", tokenSecret)
	_, err := client.CreateToken(context.Background(), "user@pve", "vault")
	if err == nil {
		t.Fatal("expected error from failing token endpoint, got nil")
	}

	if strings.Contains(err.Error(), tokenSecret) {
		t.Errorf("error string contains token_secret: %q", err.Error())
	}
}

// TestClassifyPVEErrorIntegration duplicates a few body-string cases using the
// test server to confirm the full request/error pipeline classifies correctly.
func TestClassifyPVEErrorIntegration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		statusCode int
		body       string
		endpoint   string
		method     string
		wantErr    error
	}{
		{
			name:       "user already exists via CreateUser",
			statusCode: 500,
			body:       `{"data":null,"message":"create user failed: user 'x@pve' already exists\n"}`,
			method:     http.MethodPost,
			wantErr:    ErrConflict,
		},
		{
			name:       "no such user via DeleteUser",
			statusCode: 500,
			body:       `{"data":null,"message":"no such user ('x@pve')\n"}`,
			method:     http.MethodDelete,
			wantErr:    ErrUserNotFound,
		},
		{
			name:       "forbidden via GetPermissions",
			statusCode: 403,
			body:       `{"message":"Permission check failed"}`,
			method:     http.MethodGet,
			wantErr:    ErrForbidden,
		},
		{
			name:       "unauthenticated via GetPermissions",
			statusCode: 401,
			body:       ``,
			method:     http.MethodGet,
			wantErr:    ErrUnauthenticated,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.statusCode)
				_, _ = w.Write([]byte(tc.body)) //nolint:errcheck // httptest handler — write error not actionable
			}))
			defer ts.Close()

			client := makeTestClient(t, ts.URL, "admin@pve!tok", "secret")

			var err error
			switch tc.method {
			case http.MethodPost:
				err = client.CreateUser(context.Background(), CreateUserRequest{
					UserID: "x@pve", Groups: "grp", Expire: 999, Enable: true,
				})
			case http.MethodDelete:
				err = client.DeleteUser(context.Background(), "x@pve")
			case http.MethodGet:
				_, err = client.GetPermissions(context.Background())
			}

			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("got error %v; want errors.Is(%v)", err, tc.wantErr)
			}
		})
	}
}

// TestUpdateUserRejectsUnsafeRequestsBeforeHTTP verifies the renewal safety
// guard: Enable=false or Append=false must fail before any HTTP request is sent.
func TestUpdateUserRejectsUnsafeRequestsBeforeHTTP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		req  UpdateUserRequest
	}{
		{
			name: "enable false",
			req:  UpdateUserRequest{UserID: "vault-test@pve", Expire: 999, Groups: "grp", Enable: false, Append: true},
		},
		{
			name: "append false",
			req:  UpdateUserRequest{UserID: "vault-test@pve", Expire: 999, Groups: "grp", Enable: true, Append: false},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			requestCount := 0
			ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requestCount++
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": nil}) //nolint:errcheck // httptest handler
			}))
			defer ts.Close()

			client := makeTestClient(t, ts.URL, "admin@pve!tok", "secret")
			err := client.UpdateUser(context.Background(), tc.req)
			if err == nil {
				t.Fatal("expected validation error, got nil")
			}
			if requestCount != 0 {
				t.Errorf("server saw %d requests; want 0", requestCount)
			}
		})
	}
}

// TestMockUpdateUserRejectsUnsafeRequestsBeforeLog verifies the mock enforces
// the same UpdateUserRequest validation before recording a call or invoking hooks.
func TestMockUpdateUserRejectsUnsafeRequestsBeforeLog(t *testing.T) {
	t.Parallel()

	mc := &MockClient{
		UpdateUserFn: func(context.Context, UpdateUserRequest) error {
			t.Fatal("UpdateUserFn must not be called for invalid requests")
			return nil
		},
	}

	err := mc.UpdateUser(context.Background(), UpdateUserRequest{
		UserID: "vault-test@pve",
		Expire: 999,
		Groups: "grp",
		Enable: true,
		Append: false,
	})
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
	if len(mc.CallLog) != 0 {
		t.Errorf("mock logged %d calls; want 0", len(mc.CallLog))
	}
}

// TestClientBaseURLPathConstruction asserts that the client correctly appends
// /api2/json to the address and constructs endpoint paths correctly.
func TestClientBaseURLPathConstruction(t *testing.T) {
	t.Parallel()

	var capturedPath string
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		_ = json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck // httptest handler — write error not actionable
			"data": map[string]interface{}{"version": "9.2.10"},
		})
	}))
	defer ts.Close()

	client := makeTestClient(t, ts.URL, "admin@pve!tok", "secret")
	_, err := client.GetVersion(context.Background())
	if err != nil {
		t.Fatalf("GetVersion: %v", err)
	}

	if !strings.HasPrefix(capturedPath, "/api2/json") {
		t.Errorf("request path = %q; want /api2/json prefix", capturedPath)
	}
}

// TestCreateTokenPathEncoding asserts that userid and tokenid are path-escaped
// in the URL (e.g. "vault-test@pve" → "vault-test%40pve").
func TestCreateTokenPathEncoding(t *testing.T) {
	t.Parallel()

	const userid = "vault-test@pve"
	const tokenid = "vault"

	var capturedPath string
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		_ = json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck // httptest handler — write error not actionable
			"data": map[string]interface{}{"value": "tok"},
		})
	}))
	defer ts.Close()

	client := makeTestClient(t, ts.URL, "admin@pve!tok", "secret")
	_, err := client.CreateToken(context.Background(), userid, tokenid)
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}

	wantPathSuffix := "/access/users/" + url.PathEscape(userid) + "/token/" + url.PathEscape(tokenid)
	if !strings.HasSuffix(capturedPath, wantPathSuffix) {
		t.Errorf("path = %q; want suffix %q", capturedPath, wantPathSuffix)
	}
}

// ── NewClient scheme-enforcement tests ───────────────────────────────────────

// TestNewClientRejectsHTTPScheme asserts that NewClient returns an error when
// the address uses http:// instead of https://.
// Rationale: the admin token travels in the Authorization header; over plain
// http it is exposed in cleartext and tls_skip_verify/ca_cert are meaningless.
func TestNewClientRejectsHTTPScheme(t *testing.T) {
	t.Parallel()

	_, err := NewClient(ClientConfig{
		Address:     "http://pve.example.com:8006",
		TokenID:     "vault-admin@pve!tok",
		TokenSecret: "secret",
	})
	if err == nil {
		t.Fatal("expected error for http:// address, got nil")
	}
	if !strings.Contains(err.Error(), "https") {
		t.Errorf("error should mention https requirement; got: %q", err.Error())
	}
}

// TestNewClientRejectsSchemelessAddress asserts that NewClient returns an error
// when the address has no scheme (or an empty/unknown scheme).
func TestNewClientRejectsSchemelessAddress(t *testing.T) {
	t.Parallel()

	_, err := NewClient(ClientConfig{
		Address:     "pve.example.com:8006",
		TokenID:     "vault-admin@pve!tok",
		TokenSecret: "secret",
	})
	if err == nil {
		t.Fatal("expected error for scheme-less address, got nil")
	}
	if !strings.Contains(err.Error(), "https") {
		t.Errorf("error should mention https requirement; got: %q", err.Error())
	}
}

// TestNewClientAcceptsHTTPSScheme asserts that NewClient succeeds for a valid
// https:// address (no network I/O is performed by NewClient itself).
func TestNewClientAcceptsHTTPSScheme(t *testing.T) {
	t.Parallel()

	_, err := NewClient(ClientConfig{
		Address:     "https://pve.example.com:8006",
		TokenID:     "vault-admin@pve!tok",
		TokenSecret: "secret",
	})
	if err != nil {
		t.Fatalf("expected success for https:// address; got: %v", err)
	}
}
