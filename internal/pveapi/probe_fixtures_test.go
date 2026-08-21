package pveapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// probeComment is an expected decoded value, not a captured response body.
const probeComment = "vault-wal:PROBECOMMENT12345"

// These fixtures are copied byte-for-byte from the raw evidence blocks in
// docs/PVE_PROBES.md. Keep them as raw strings: JSON re-encoding would hide
// changes to field order, escaped newlines, or whitespace in PVE responses.
const (
	probe1PermissionsResponse    = `{"data":{"/access/realm/pve":{"Realm.AllocateUser":1,"User.Modify":1,"Sys.Audit":1},"/access/groups":{"Realm.AllocateUser":1,"User.Modify":1,"Sys.Audit":1}}}`
	probe9NonPropagatingResponse = `{"data":{"/access/groups":{"Realm.AllocateUser":0,"User.Modify":0,"Sys.Audit":0}}}`

	probe2DuplicateUserResponse = `{"data":null,"message":"create user failed: user 'probe-dup-52445741@pve' already exists\n"}`
	// Probes 3 and 4 genuinely returned the same body for different methods.
	probe3MissingUserResponse  = `{"data":null,"message":"no such user ('probe-ghost-nonexistent@pve')\n"}`
	probe4MissingUserResponse  = `{"data":null,"message":"no such user ('probe-ghost-nonexistent@pve')\n"}`
	probe5MissingGroupResponse = `{"data":null,"message":"group 'definitely-not-a-real-group' does not exist\n"}`
	// Probe 6's conclusion is marked flawed in PVE_PROBES.md (see Probe 6-fix).
	// This is nevertheless the verbatim body for the unscoped request made by
	// GetPermissions; an empty tree is not evidence that group permissions fail.
	probe6EmptyPermissionsResponse = `{"data":{}}`
	probe6bDuplicateTokenResponse  = `{"message":"Parameter verification failed.\n","data":null,"errors":{"tokenid":"Token already exists."}}`

	groupAddUserResponse  = `{"data":{"enable":1,"expire":1786972261,"tokens":null,"groups":["vault-test-grp"]}}`
	groupAddGroupResponse = `{"data":{"comment":"Vault dynamic-cred test group","members":["probe-ga-7mqj5nzp@pve"]}}`

	commentAfterCreateResponse  = `{"data":{"comment":"vault-wal:PROBECOMMENT12345","enable":1,"expire":1787108586,"groups":["vault-test-grp"],"tokens":null}}`
	commentAfterRenewalResponse = `{"data":{"comment":"vault-wal:PROBECOMMENT12345","enable":1,"expire":1787112186,"groups":["vault-test-grp"],"tokens":null}}`

	renewalPreserveBeforeResponse = `{"data":{"tokens":null,"enable":1,"groups":["vault-test-grp"],"expire":1786986804}}`
	renewalPreserveAfterResponse  = `{"data":{"enable":1,"groups":["vault-test-grp"],"tokens":null,"expire":1786990429}}`

	// Probe 0 — GET /version, the reachability/TLS check run at config write.
	probe0VersionResponse = `{"data":{"version":"9.2.10","release":"9.2","repoid":"43df2e01f27a1a19"}}`

	// Probe 1b — GET /access/permissions?path=<p>. The engine does NOT use the
	// scoped form; this body is captured because PVE echoes the requested path
	// back with a TRAILING SLASH. HasPrivilege normalizes the path it is ASKED
	// about but not the tree's own keys, so a tree built from this response
	// would not answer for "/access/groups". That is the documented reason the
	// engine parses the unscoped dump and walks ancestors itself.
	probe1bScopedPathResponse = `{"data":{"/access/groups/":{"Sys.Audit":1,"User.Modify":1,"Realm.AllocateUser":1}}}`

	// Probe 6-fix C/D — HTTP 403 permission-check failures. The pair differs
	// ONLY in JSON key order, which classification must not depend on.
	probe6fixForbiddenResponse         = `{"data":null,"message":"Permission check failed (/access, Sys.Audit)\n"}`
	probe6fixForbiddenKeyOrderResponse = `{"message":"Permission check failed (/access, Sys.Audit)\n","data":null}`

	// Probe CLEAN 5-C — POST /access/users/{userid}/token/{tokenid} success.
	// `value` carries the one-time token secret. This particular secret belongs
	// to a throwaway user on the disposable probe cluster that the probe's own
	// cleanup step deleted; it is already recorded in docs/PVE_PROBES.md.
	// Note `info.privsep` echoes back as the STRING "0", not the number 0.
	cleanTokenCreateResponse = `{"data":{"full-tokenid":"probe-clean-dcq47dxi@pve!vault","info":{"privsep":"0"},"value":"625f6f0a-4179-4796-99b9-3f3f71eb2ce0"}}`

	// Mutating endpoints (POST/PUT/DELETE) answer HTTP 200 with a null data
	// field — captured at Probe 7-fix A/C and Probe CLEAN 2-A/6-A.
	mutationSuccessResponse = `{"data":null}`

	// Probe 6-fix A / CLEAN 5-B — a permission dump where the path IS present
	// but carries no privileges. Guards against treating "path exists" as
	// "privilege held".
	cleanRootEmptyPermissionsResponse = `{"data":{"/":{}}}`

	// The empty-`groups` family. Every one of these is a real captured
	// read-back in which PVE reported the user as holding NO group membership
	// — Probe 7 (expire-only PUT wiped groups), Probe 7-fix B (still empty
	// after re-sending groups=), and Probe CLEAN 3-A/4-A/6-B (membership never
	// landed at creation). These are the exact wire shapes the issuance and
	// renewal read-back assertions exist to catch, so they are replayed through
	// GetUser to prove the assertions fire on real PVE output. Note the family
	// varies both in key order and in `tokens` (null vs a populated object).
	probe7GroupsWipedResponse       = `{"data":{"expire":1786966464,"enable":1,"groups":[],"tokens":{"vault":{"expire":0,"privsep":0}}}}`
	probe7fixGroupsWipedResponse    = `{"data":{"groups":[],"tokens":null,"enable":1,"expire":1786968440}}`
	cleanCreateGroupsEmptyResponse  = `{"data":{"groups":[],"tokens":null,"expire":1786970429,"enable":1}}`
	cleanAppendGroupsEmptyResponse  = `{"data":{"enable":1,"expire":1786970429,"groups":[],"tokens":null}}`
	cleanRenewalGroupsEmptyResponse = `{"data":{"expire":1786974355,"enable":1,"tokens":{"vault":{"expire":0,"privsep":0}},"groups":[]}}`
)

// TestProbeFixturesRemainRawJSON guards against fixture drift from the raw
// evidence in docs/PVE_PROBES.md, as well as accidental line-ending changes.
func TestProbeFixturesRemainRawJSON(t *testing.T) {
	t.Parallel()

	fixtures := []struct {
		name string
		body string
	}{
		{name: "Probe 1", body: probe1PermissionsResponse},
		{name: "Probe 9 non-propagating permissions", body: probe9NonPropagatingResponse},
		{name: "Probe 2", body: probe2DuplicateUserResponse},
		{name: "Probe 3", body: probe3MissingUserResponse},
		{name: "Probe 4", body: probe4MissingUserResponse},
		{name: "Probe 5", body: probe5MissingGroupResponse},
		{name: "Probe 6 empty permissions (unscoped response)", body: probe6EmptyPermissionsResponse},
		{name: "Probe 6b", body: probe6bDuplicateTokenResponse},
		{name: "GROUPADD user", body: groupAddUserResponse},
		{name: "GROUPADD group", body: groupAddGroupResponse},
		{name: "RENEWAL-PRESERVE before", body: renewalPreserveBeforeResponse},
		{name: "RENEWAL-PRESERVE after", body: renewalPreserveAfterResponse},
		{name: "COMMENT after create", body: commentAfterCreateResponse},
		{name: "COMMENT after renewal", body: commentAfterRenewalResponse},
		{name: "Probe 0 version", body: probe0VersionResponse},
		{name: "Probe 1b scoped path (trailing slash)", body: probe1bScopedPathResponse},
		{name: "Probe 6-fix forbidden", body: probe6fixForbiddenResponse},
		{name: "Probe 6-fix forbidden (key order swapped)", body: probe6fixForbiddenKeyOrderResponse},
		{name: "Probe CLEAN token create", body: cleanTokenCreateResponse},
		{name: "mutation success (data:null)", body: mutationSuccessResponse},
		{name: "root path present but empty", body: cleanRootEmptyPermissionsResponse},
		{name: "Probe 7 groups wiped", body: probe7GroupsWipedResponse},
		{name: "Probe 7-fix groups still empty", body: probe7fixGroupsWipedResponse},
		{name: "Probe CLEAN 3-A groups empty at create", body: cleanCreateGroupsEmptyResponse},
		{name: "Probe CLEAN 4-A groups empty after append", body: cleanAppendGroupsEmptyResponse},
		{name: "Probe CLEAN 6-B groups empty after renewal", body: cleanRenewalGroupsEmptyResponse},
	}
	docs, err := os.ReadFile("../../docs/PVE_PROBES.md")
	if err != nil {
		t.Fatalf("read probe source: %v", err)
	}

	for _, fixture := range fixtures {
		fixture := fixture
		t.Run(fixture.name, func(t *testing.T) {
			t.Parallel()
			if !json.Valid([]byte(fixture.body)) {
				t.Fatal("fixture is not valid JSON")
			}
			if strings.ContainsAny(fixture.body, "\r\n") {
				t.Fatal("fixture contains a literal line ending; preserve the documented bytes")
			}
			if !strings.Contains(string(docs), fixture.body) {
				t.Fatal("fixture no longer appears byte-for-byte in docs/PVE_PROBES.md")
			}
		})
	}
}

// TestGroupAddGroupFixtureThroughRealClient verifies GetGroup's request shape
// and HTTP 200 -> nil contract. GetGroup intentionally discards the response;
// the fixture body itself is guarded only by TestProbeFixturesRemainRawJSON.
func TestGroupAddGroupFixtureThroughRealClient(t *testing.T) {
	t.Parallel()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api2/json/access/groups/vault-test-grp" {
			t.Errorf("request = %s %s; want GET /api2/json/access/groups/vault-test-grp", r.Method, r.URL.Path)
		}
		_, _ = w.Write([]byte(groupAddGroupResponse)) //nolint:errcheck // httptest handler
	}))
	defer ts.Close()
	if err := makeTestClient(t, ts.URL, "admin@pve!tok", "secret").GetGroup(context.Background(), "vault-test-grp"); err != nil {
		t.Fatalf("GetGroup: %v", err)
	}
}

// serveFixture spins up a TLS test server that answers every request with the
// given status and captured body, asserting the method and path the engine is
// expected to use.
func serveFixture(t *testing.T, status int, body, wantMethod, wantPath string) Client {
	t.Helper()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != wantMethod || r.URL.Path != wantPath {
			t.Errorf("request = %s %s; want %s %s", r.Method, r.URL.Path, wantMethod, wantPath)
		}
		if status != http.StatusOK {
			w.WriteHeader(status)
		}
		_, _ = w.Write([]byte(body)) //nolint:errcheck // httptest handler
	}))
	t.Cleanup(ts.Close)
	return makeTestClient(t, ts.URL, "admin@pve!tok", "secret")
}

// TestProbeVersionFixtureThroughRealClient replays the Probe 0 body and asserts
// GetVersion extracts the version string that config-write reports.
func TestProbeVersionFixtureThroughRealClient(t *testing.T) {
	t.Parallel()

	client := serveFixture(t, http.StatusOK, probe0VersionResponse, http.MethodGet, "/api2/json/version")
	version, err := client.GetVersion(context.Background())
	if err != nil {
		t.Fatalf("GetVersion: %v", err)
	}
	if version != "9.2.10" {
		t.Errorf("version = %q; want %q", version, "9.2.10")
	}
}

// TestProbeTokenCreateFixtureThroughRealClient replays the Probe CLEAN 5-C
// token-creation body and asserts CreateToken returns the `value` field. The
// captured response also carries `full-tokenid` and `info.privsep` (the STRING
// "0"); neither must be mistaken for the secret.
func TestProbeTokenCreateFixtureThroughRealClient(t *testing.T) {
	t.Parallel()

	const (
		userid    = "probe-clean-dcq47dxi@pve"
		wantValue = "625f6f0a-4179-4796-99b9-3f3f71eb2ce0"
	)

	client := serveFixture(t, http.StatusOK, cleanTokenCreateResponse,
		http.MethodPost, "/api2/json/access/users/"+userid+"/token/vault")

	secret, err := client.CreateToken(context.Background(), userid, "vault")
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	if secret != wantValue {
		t.Errorf("token secret = %q; want the response's `value` field %q", secret, wantValue)
	}
}

// TestProbeForbiddenFixturesThroughRealClient replays the Probe 6-fix C/D
// permission-check failures. HTTP 403 is a genuine status that must classify as
// ErrForbidden before any body-string matching, and the two captured bodies
// differ only in JSON key order — classification must not depend on it.
func TestProbeForbiddenFixturesThroughRealClient(t *testing.T) {
	t.Parallel()

	tests := []struct{ name, body string }{
		{name: "6-fix-C", body: probe6fixForbiddenResponse},
		{name: "6-fix-D (key order swapped)", body: probe6fixForbiddenKeyOrderResponse},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Through the real client.
			client := serveFixture(t, http.StatusForbidden, tc.body,
				http.MethodGet, "/api2/json/access/permissions")
			if _, err := client.GetPermissions(context.Background()); !errors.Is(err, ErrForbidden) {
				t.Errorf("GetPermissions error = %v; want errors.Is(ErrForbidden)", err)
			}

			// And directly through the classifier.
			if err := classifyPVEError(http.StatusForbidden, []byte(tc.body)); !errors.Is(err, ErrForbidden) {
				t.Errorf("classifyPVEError = %v; want errors.Is(ErrForbidden)", err)
			}
		})
	}
}

// TestProbeMutationSuccessFixtureThroughRealClient replays the `{"data":null}`
// body that every mutating PVE endpoint returns on success (Probe 7-fix A/C,
// Probe CLEAN 2-A/6-A) and asserts each mutating client method treats it as
// success rather than as a missing-payload parse error.
func TestProbeMutationSuccessFixtureThroughRealClient(t *testing.T) {
	t.Parallel()

	const userid = "probe-clean-dcq47dxi@pve"

	tests := []struct {
		name, wantMethod, wantPath string
		call                       func(Client) error
	}{
		{
			name: "CreateUser", wantMethod: http.MethodPost, wantPath: "/api2/json/access/users",
			call: func(c Client) error {
				return c.CreateUser(context.Background(), CreateUserRequest{
					UserID: userid, Groups: "vault-test-grp", Expire: 1786970429, Enable: true,
				})
			},
		},
		{
			name: "UpdateUser", wantMethod: http.MethodPut, wantPath: "/api2/json/access/users/" + userid,
			call: func(c Client) error {
				return c.UpdateUser(context.Background(), UpdateUserRequest{
					UserID: userid, Expire: 1786974355, Groups: "vault-test-grp", Enable: true, Append: true,
				})
			},
		},
		{
			name: "DeleteUser", wantMethod: http.MethodDelete, wantPath: "/api2/json/access/users/" + userid,
			call: func(c Client) error { return c.DeleteUser(context.Background(), userid) },
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			client := serveFixture(t, http.StatusOK, mutationSuccessResponse, tc.wantMethod, tc.wantPath)
			if err := tc.call(client); err != nil {
				t.Fatalf("%s on captured success body: %v", tc.name, err)
			}
		})
	}
}

// TestProbeEmptyGroupsFixturesThroughRealClient replays every captured
// read-back in which PVE reported the user as holding NO group membership.
//
// This is the load-bearing case for the issuance and renewal read-back
// assertions: PVE answers HTTP 200 while silently dropping the group, so the
// ONLY signal is an empty `groups` array in the body. Replaying the real
// captures proves the assertions fire on actual PVE wire output rather than on
// a hand-authored `groups: []`. The family also varies in key order and in
// `tokens` (null vs a populated object), so parsing must not depend on either.
func TestProbeEmptyGroupsFixturesThroughRealClient(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		body       string
		wantEnable bool
		wantExpire int64
	}{
		{name: "Probe 7 expire-only PUT wiped groups", body: probe7GroupsWipedResponse, wantEnable: true, wantExpire: 1786966464},
		{name: "Probe 7-fix B still empty after re-sending groups", body: probe7fixGroupsWipedResponse, wantEnable: true, wantExpire: 1786968440},
		{name: "Probe CLEAN 3-A empty at creation", body: cleanCreateGroupsEmptyResponse, wantEnable: true, wantExpire: 1786970429},
		{name: "Probe CLEAN 4-A empty after append=1", body: cleanAppendGroupsEmptyResponse, wantEnable: true, wantExpire: 1786970429},
		{name: "Probe CLEAN 6-B empty after renewal", body: cleanRenewalGroupsEmptyResponse, wantEnable: true, wantExpire: 1786974355},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			client := serveFixture(t, http.StatusOK, tc.body, http.MethodGet, "/api2/json/access/users/probe@pve")
			info, err := client.GetUser(context.Background(), "probe@pve")
			if err != nil {
				t.Fatalf("GetUser: %v", err)
			}

			// The read-back assertion's trip condition.
			if len(info.Groups) != 0 {
				t.Errorf("groups = %#v; want empty (this capture recorded a dropped membership)", info.Groups)
			}
			if info.Enable != tc.wantEnable {
				t.Errorf("enable = %t; want %t", info.Enable, tc.wantEnable)
			}
			if info.Expire != tc.wantExpire {
				t.Errorf("expire = %d; want %d", info.Expire, tc.wantExpire)
			}
		})
	}
}

// TestProbeEmptyPermissionPathFixtureThroughRealClient replays a dump in which
// the ACL path IS present but carries no privileges (Probe 6-fix A, Probe CLEAN
// 5-B). Path presence must never be read as privilege possession.
func TestProbeEmptyPermissionPathFixtureThroughRealClient(t *testing.T) {
	t.Parallel()

	client := serveFixture(t, http.StatusOK, cleanRootEmptyPermissionsResponse,
		http.MethodGet, "/api2/json/access/permissions")

	tree, err := client.GetPermissions(context.Background())
	if err != nil {
		t.Fatalf("GetPermissions: %v", err)
	}
	assertPermissionTree(t, tree, PermissionTree{"/": {}})

	for _, priv := range []string{"User.Modify", "Sys.Audit", "Realm.AllocateUser"} {
		if tree.HasPrivilege("/access/groups", priv) {
			t.Errorf("HasPrivilege(/access/groups, %s) = true; want false for a present-but-empty path", priv)
		}
	}
}

// TestProbeScopedPathFixtureDoesNotSatisfyAncestorWalk replays the Probe 1b
// `?path=` response. PVE echoes the requested path back with a TRAILING SLASH,
// so a tree built from the scoped form does not answer HasPrivilege queries for
// the unsuffixed path. This is the recorded reason the engine parses the
// UNSCOPED /access/permissions dump and walks ancestors itself rather than
// delegating resolution to PVE via `?path=`.
func TestProbeScopedPathFixtureDoesNotSatisfyAncestorWalk(t *testing.T) {
	t.Parallel()

	client := serveFixture(t, http.StatusOK, probe1bScopedPathResponse,
		http.MethodGet, "/api2/json/access/permissions")

	tree, err := client.GetPermissions(context.Background())
	if err != nil {
		t.Fatalf("GetPermissions: %v", err)
	}
	assertPermissionTree(t, tree, PermissionTree{
		"/access/groups/": {"Sys.Audit": 1, "User.Modify": 1, "Realm.AllocateUser": 1},
	})

	if tree.HasPrivilege("/access/groups", "User.Modify") {
		t.Error("HasPrivilege matched the trailing-slash key; the engine must not depend on the ?path= form")
	}
}
