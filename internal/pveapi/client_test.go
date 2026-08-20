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
	"slices"
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

type unsafeUpdateUserCase struct {
	name       string
	req        UpdateUserRequest
	wantReason string
}

var unsafeUpdateUserCases = []unsafeUpdateUserCase{
	{
		name:       "expire zero",
		req:        UpdateUserRequest{UserID: "vault-test@pve", Expire: 0, Groups: "grp", Enable: true, Append: true},
		wantReason: "expire=0",
	},
	{
		name:       "expire negative",
		req:        UpdateUserRequest{UserID: "vault-test@pve", Expire: -1, Groups: "grp", Enable: true, Append: true},
		wantReason: "expire=-1",
	},
	{
		name:       "groups empty",
		req:        UpdateUserRequest{UserID: "vault-test@pve", Expire: 999, Groups: "", Enable: true, Append: true},
		wantReason: "groups is empty",
	},
	{
		name:       "groups whitespace",
		req:        UpdateUserRequest{UserID: "vault-test@pve", Expire: 999, Groups: "   ", Enable: true, Append: true},
		wantReason: "groups is empty",
	},
	{
		name:       "enable false",
		req:        UpdateUserRequest{UserID: "vault-test@pve", Expire: 999, Groups: "grp", Enable: false, Append: true},
		wantReason: "enable=false",
	},
	{
		name:       "append false",
		req:        UpdateUserRequest{UserID: "vault-test@pve", Expire: 999, Groups: "grp", Enable: true, Append: false},
		wantReason: "append=false",
	},
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

// TestGetPermissionsParsesTree parses captured Probe 1 permissions and
// verifies the privileges and propagation needed by config and role checks.
func TestGetPermissionsParsesTree(t *testing.T) {
	t.Parallel()

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api2/json/access/permissions" {
			t.Errorf("unexpected path: %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(probe1PermissionsResponse)) //nolint:errcheck // httptest handler
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
	if !tree.HasPrivilege("/access/groups/vault-test-grp", "User.Modify") {
		t.Error("expected User.Modify to propagate to /access/groups/vault-test-grp")
	}
}

// TestProbeNonPropagatingPermissionsFixtureThroughRealClient replays captured
// Probe 9 evidence and verifies that an exact-path privilege remains effective
// while the same non-propagating grant is rejected for a child group path.
func TestProbeNonPropagatingPermissionsFixtureThroughRealClient(t *testing.T) {
	t.Parallel()

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api2/json/access/permissions" {
			t.Errorf("request = %s %s; want GET /api2/json/access/permissions", r.Method, r.URL.Path)
		}
		_, _ = w.Write([]byte(probe9NonPropagatingResponse)) //nolint:errcheck // httptest handler
	}))
	defer ts.Close()

	tree, err := makeTestClient(t, ts.URL, "admin@pve!tok", "secret").GetPermissions(context.Background())
	if err != nil {
		t.Fatalf("GetPermissions: %v", err)
	}
	if !tree.HasPrivilege("/access/groups", "User.Modify") {
		t.Error("expected User.Modify at the exact /access/groups path")
	}
	if tree.HasPrivilege("/access/groups/vault-test-grp", "User.Modify") {
		t.Error("did not expect User.Modify to propagate to /access/groups/vault-test-grp")
	}
}

// TestGetUserParsesGroupsArrayResponse asserts that the real HTTP client
// accepts the PVE 9.2.10 GET /access/users/{userid} response shape, where
// data.groups is a JSON array, and normalizes it into UserInfo.Groups.
func TestGetUserParsesGroupsArrayResponse(t *testing.T) {
	t.Parallel()

	const userid = "vault-test@pve"
	const wantComment = "vault-wal:test-nonce"
	const wantExpire int64 = 1790000000

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wantPath := "/api2/json/access/users/" + url.PathEscape(userid)
		if r.URL.Path != wantPath {
			t.Errorf("request path = %q; want %q", r.URL.Path, wantPath)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck // httptest handler — write error not actionable
			"data": map[string]interface{}{
				"groups":  []string{"vault-test-grp", "audit-grp"},
				"enable":  1,
				"expire":  wantExpire,
				"comment": wantComment,
			},
		})
	}))
	defer ts.Close()

	client := makeTestClient(t, ts.URL, "admin@pve!tok", "secret")
	info, err := client.GetUser(context.Background(), userid)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}

	wantGroups := []string{"vault-test-grp", "audit-grp"}
	if !slices.Equal(info.Groups, wantGroups) {
		t.Errorf("groups = %#v; want %#v", info.Groups, wantGroups)
	}
	if !info.Enable {
		t.Error("enable = false; want true")
	}
	if info.Expire != wantExpire {
		t.Errorf("expire = %d; want %d", info.Expire, wantExpire)
	}
	if info.Comment != wantComment {
		t.Errorf("comment = %q; want %q", info.Comment, wantComment)
	}
}

// TestGetUserParsesLegacyCSVAndNullGroups preserves compatibility with older
// or empty PVE user responses while the target PVE 9.2.10 shape is an array.
func TestGetUserParsesLegacyCSVAndNullGroups(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		groupsJSON string
		wantGroups []string
	}{
		{
			name:       "legacy csv string",
			groupsJSON: `"grp-a, grp-b,,"`,
			wantGroups: []string{"grp-a", "grp-b"},
		},
		{
			name:       "null groups",
			groupsJSON: `null`,
			wantGroups: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"data":{"groups":` + tc.groupsJSON + `,"enable":0,"expire":0,"comment":""}}`)) //nolint:errcheck // httptest handler — write error not actionable
			}))
			defer ts.Close()

			client := makeTestClient(t, ts.URL, "admin@pve!tok", "secret")
			info, err := client.GetUser(context.Background(), "vault-test@pve")
			if err != nil {
				t.Fatalf("GetUser: %v", err)
			}

			if !slices.Equal(info.Groups, tc.wantGroups) {
				t.Errorf("groups = %#v; want %#v", info.Groups, tc.wantGroups)
			}
		})
	}
}

// TestGetUserRejectsMalformedGroupsType rejects unexpected groups payloads
// rather than silently normalizing a shape PVE does not document for users.
func TestGetUserRejectsMalformedGroupsType(t *testing.T) {
	t.Parallel()

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"groups":{"bad":"shape"},"enable":1,"expire":1,"comment":""}}`)) //nolint:errcheck // httptest handler — write error not actionable
	}))
	defer ts.Close()

	client := makeTestClient(t, ts.URL, "admin@pve!tok", "secret")
	_, err := client.GetUser(context.Background(), "vault-test@pve")
	if err == nil {
		t.Fatal("expected malformed groups parse error, got nil")
	}
	if !strings.Contains(err.Error(), "parse response") {
		t.Errorf("error = %q; want parse response context", err.Error())
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
			body:       `{"message":"no such user, but token auth failed first"}`,
			method:     http.MethodGet,
			wantErr:    ErrUnauthenticated,
		},
	}

	for _, tc := range tests {
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

type probeClientErrorCase struct {
	name       string
	status     int
	body       string
	wantMethod string
	wantPath   string
	call       func(Client) error
	wantErr    error
}

var probeClientErrorCases = []probeClientErrorCase{
	{name: "Probe 2 duplicate user", status: 500, body: probe2DuplicateUserResponse, wantMethod: http.MethodPost, wantPath: "/api2/json/access/users", call: func(client Client) error {
		return client.CreateUser(context.Background(), CreateUserRequest{UserID: "probe-dup-52445741@pve", Groups: "grp", Expire: 1, Enable: true})
	}, wantErr: ErrConflict},
	{name: "Probe 3 missing user delete", status: 500, body: probe3MissingUserResponse, wantMethod: http.MethodDelete, wantPath: "/api2/json/access/users/probe-ghost-nonexistent@pve", call: func(client Client) error {
		return client.DeleteUser(context.Background(), "probe-ghost-nonexistent@pve")
	}, wantErr: ErrUserNotFound},
	{name: "Probe 4 missing user get", status: 500, body: probe4MissingUserResponse, wantMethod: http.MethodGet, wantPath: "/api2/json/access/users/probe-ghost-nonexistent@pve", call: func(client Client) error {
		_, err := client.GetUser(context.Background(), "probe-ghost-nonexistent@pve")
		return err
	}, wantErr: ErrUserNotFound},
	{name: "Probe 5 missing group", status: 500, body: probe5MissingGroupResponse, wantMethod: http.MethodGet, wantPath: "/api2/json/access/groups/definitely-not-a-real-group", call: func(client Client) error {
		return client.GetGroup(context.Background(), "definitely-not-a-real-group")
	}, wantErr: ErrGroupNotFound},
	{name: "Probe 6b duplicate token", status: 400, body: probe6bDuplicateTokenResponse, wantMethod: http.MethodPost, wantPath: "/api2/json/access/users/probe-ps-52445741@pve/token/vault", call: func(client Client) error {
		_, err := client.CreateToken(context.Background(), "probe-ps-52445741@pve", "vault")
		return err
	}, wantErr: ErrConflict},
}

func runProbeClientError(t *testing.T, tc probeClientErrorCase) {
	t.Helper()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != tc.wantMethod || r.URL.Path != tc.wantPath {
			t.Errorf("request = %s %s; want %s %s", r.Method, r.URL.Path, tc.wantMethod, tc.wantPath)
		}
		w.WriteHeader(tc.status)
		_, _ = w.Write([]byte(tc.body)) //nolint:errcheck // httptest handler
	}))
	defer ts.Close()
	err := tc.call(makeTestClient(t, ts.URL, "admin@pve!tok", "secret"))
	if !errors.Is(err, tc.wantErr) {
		t.Fatalf("error = %v; want errors.Is(%v)", err, tc.wantErr)
	}
}

// TestProbeErrorFixturesThroughRealClient replays the verbatim error bodies
// from PVE_PROBES.md through the corresponding real-client methods. The
// classifier-only table preserves generalized malformed/status coverage.
func TestProbeErrorFixturesThroughRealClient(t *testing.T) {
	t.Parallel()
	for _, tc := range probeClientErrorCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) { t.Parallel(); runProbeClientError(t, tc) })
	}
}

// assertPermissionTree verifies every captured permission path and privilege.
func assertPermissionTree(t *testing.T, got, want PermissionTree) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("permission paths = %d; want %d", len(got), len(want))
	}
	for path, wantPrivileges := range want {
		gotPrivileges, ok := got[path]
		if !ok {
			t.Fatalf("missing permission path %q", path)
		}
		if len(gotPrivileges) != len(wantPrivileges) {
			t.Fatalf("privileges at %q = %#v; want %#v", path, gotPrivileges, wantPrivileges)
		}
		for privilege, wantFlag := range wantPrivileges {
			if gotPrivileges[privilege] != wantFlag {
				t.Errorf("permission %q at %q = %d; want %d", privilege, path, gotPrivileges[privilege], wantFlag)
			}
		}
	}
}

// TestProbePermissionsFixturesThroughRealClient parses the exact Probe 1 and
// Probe 6 permissions responses and asserts every captured permission entry.
func TestProbePermissionsFixturesThroughRealClient(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, body string
		want       PermissionTree
	}{
		{name: "Probe 1 permissions", body: probe1PermissionsResponse, want: PermissionTree{
			"/access/realm/pve": {"Realm.AllocateUser": 1, "User.Modify": 1, "Sys.Audit": 1},
			"/access/groups":    {"Realm.AllocateUser": 1, "User.Modify": 1, "Sys.Audit": 1},
		}},
		{name: "Probe 6 empty permissions (unscoped response)", body: probe6EmptyPermissionsResponse, want: PermissionTree{}},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/api2/json/access/permissions" {
					t.Errorf("request = %s %s; want GET /api2/json/access/permissions", r.Method, r.URL.Path)
				}
				_, _ = w.Write([]byte(tc.body)) //nolint:errcheck // httptest handler
			}))
			defer ts.Close()
			tree, err := makeTestClient(t, ts.URL, "admin@pve!tok", "secret").GetPermissions(context.Background())
			if err != nil {
				t.Fatalf("GetPermissions: %v", err)
			}
			assertPermissionTree(t, tree, tc.want)
		})
	}
}

// TestProbeUserFixturesThroughRealClient replays GROUPADD, COMMENT, and
// RENEWAL-PRESERVE user responses and asserts all fields consumed by the
// issuance and renewal read-back checks.
func TestProbeUserFixturesThroughRealClient(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		body        string
		wantGroups  []string
		wantEnable  bool
		wantExpire  int64
		wantComment string
	}{
		{name: "GROUPADD user read-back", body: groupAddUserResponse, wantGroups: []string{"vault-test-grp"}, wantEnable: true, wantExpire: 1786972261},
		{name: "COMMENT after create", body: commentAfterCreateResponse, wantGroups: []string{"vault-test-grp"}, wantEnable: true, wantExpire: 1787108586, wantComment: probeComment},
		{name: "COMMENT after renewal", body: commentAfterRenewalResponse, wantGroups: []string{"vault-test-grp"}, wantEnable: true, wantExpire: 1787112186, wantComment: probeComment},
		{name: "RENEWAL-PRESERVE before", body: renewalPreserveBeforeResponse, wantGroups: []string{"vault-test-grp"}, wantEnable: true, wantExpire: 1786986804},
		{name: "RENEWAL-PRESERVE after", body: renewalPreserveAfterResponse, wantGroups: []string{"vault-test-grp"}, wantEnable: true, wantExpire: 1786990429},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/api2/json/access/users/probe@pve" {
					t.Errorf("request = %s %s; want GET /api2/json/access/users/probe@pve", r.Method, r.URL.Path)
				}
				_, _ = w.Write([]byte(tc.body)) //nolint:errcheck // httptest handler
			}))
			defer ts.Close()

			info, err := makeTestClient(t, ts.URL, "admin@pve!tok", "secret").GetUser(context.Background(), "probe@pve")
			if err != nil {
				t.Fatalf("GetUser: %v", err)
			}
			if !slices.Equal(info.Groups, tc.wantGroups) || info.Enable != tc.wantEnable || info.Expire != tc.wantExpire {
				t.Fatalf("user info = %#v; want groups=%#v enable=%t expire=%d", info, tc.wantGroups, tc.wantEnable, tc.wantExpire)
			}
			if info.Comment != tc.wantComment {
				t.Errorf("comment = %q; want %q", info.Comment, tc.wantComment)
			}
		})
	}
}

// TestUpdateUserRejectsUnsafeRequestsBeforeHTTP verifies the renewal safety
// guard: unsafe expire, groups, enable, or append values must fail before any
// HTTP request is sent.
func TestUpdateUserRejectsUnsafeRequestsBeforeHTTP(t *testing.T) {
	t.Parallel()

	for _, tc := range unsafeUpdateUserCases {
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
			if !strings.Contains(err.Error(), tc.wantReason) {
				t.Errorf("validation error should mention %q; got %q", tc.wantReason, err.Error())
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

	for _, tc := range unsafeUpdateUserCases {
		t.Run(tc.name, func(t *testing.T) {
			err := mc.UpdateUser(context.Background(), tc.req)
			if err == nil {
				t.Fatal("expected validation error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantReason) {
				t.Errorf("validation error should mention %q; got %q", tc.wantReason, err.Error())
			}
			if len(mc.CallLog) != 0 {
				t.Errorf("mock logged %d calls; want 0", len(mc.CallLog))
			}
		})
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

// TestClientAcceptsNormalSizedResponse verifies ordinary small PVE JSON
// responses remain readable with the response-size guard in place.
func TestClientAcceptsNormalSizedResponse(t *testing.T) {
	t.Parallel()

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck // httptest handler — write error not actionable
			"data": map[string]interface{}{"version": "9.2.10"},
		})
	}))
	defer ts.Close()

	client := makeTestClient(t, ts.URL, "admin@pve!tok", "secret")
	version, err := client.GetVersion(context.Background())
	if err != nil {
		t.Fatalf("GetVersion: %v", err)
	}
	if version != "9.2.10" {
		t.Errorf("version = %q; want %q", version, "9.2.10")
	}
}

// TestClientRejectsOversizedResponse verifies a malicious or broken endpoint
// cannot force the client to read an unbounded response body into memory.
func TestClientRejectsOversizedResponse(t *testing.T) {
	t.Parallel()

	const oversizedSentinel = "oversized-body-sentinel"

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		tooLargeBody := strings.Repeat(oversizedSentinel, maxResponseBodyBytes/len(oversizedSentinel)+2)
		_, _ = w.Write([]byte(tooLargeBody)) //nolint:errcheck // httptest handler — write error not actionable
	}))
	defer ts.Close()

	client := makeTestClient(t, ts.URL, "admin@pve!tok", "secret")
	_, err := client.GetVersion(context.Background())
	if err == nil {
		t.Fatal("expected oversized response error, got nil")
	}
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Errorf("error = %v; want errors.Is(ErrResponseTooLarge)", err)
	}
	if strings.Contains(err.Error(), oversizedSentinel) {
		t.Errorf("error should not include oversized body content; got %q", err.Error())
	}
}

// TestReadResponseBodyBoundarySizes pins the N+1 cap check: cap-1 and cap
// bytes are accepted, while cap+1 returns the typed response-size sentinel.
func TestReadResponseBodyBoundarySizes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		size    int
		wantErr bool
	}{
		{name: "cap minus one", size: maxResponseBodyBytes - 1, wantErr: false},
		{name: "exactly cap", size: maxResponseBodyBytes, wantErr: false},
		{name: "cap plus one", size: maxResponseBodyBytes + 1, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			body, err := readResponseBody(strings.NewReader(strings.Repeat("a", tc.size)))
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected response-size error, got nil")
				}
				if !errors.Is(err, ErrResponseTooLarge) {
					t.Fatalf("error = %v; want errors.Is(ErrResponseTooLarge)", err)
				}
				if body != nil {
					t.Fatalf("body length = %d; want nil body", len(body))
				}
				return
			}

			if err != nil {
				t.Fatalf("readResponseBody returned unexpected error: %v", err)
			}
			if len(body) != tc.size {
				t.Fatalf("body length = %d; want %d", len(body), tc.size)
			}
		})
	}
}

// TestOversizedDeleteUserFailsBeforeBusinessClassification verifies the cap is
// fail-closed: even a DELETE response containing PVE's idempotent
// "no such user" body-string is not mapped to ErrUserNotFound unless the full
// response fits inside the bound.
func TestOversizedDeleteUserFailsBeforeBusinessClassification(t *testing.T) {
	t.Parallel()

	message := `{"data":null,"message":"no such user ('x@pve')\n","padding":"`
	oversizedBody := message + strings.Repeat("a", maxResponseBodyBytes-len(message)+1) + `"}`

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(oversizedBody)) //nolint:errcheck // httptest handler — write error not actionable
	}))
	defer ts.Close()

	client := makeTestClient(t, ts.URL, "admin@pve!tok", "secret")
	err := client.DeleteUser(context.Background(), "x@pve")
	if err == nil {
		t.Fatal("expected oversized response error, got nil")
	}
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("error = %v; want errors.Is(ErrResponseTooLarge)", err)
	}
	if errors.Is(err, ErrUserNotFound) {
		t.Fatalf("oversized delete response was classified as ErrUserNotFound: %v", err)
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
