package pveapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// These fixtures are copied byte-for-byte from the raw evidence blocks in
// docs/PVE_PROBES.md. Keep them as raw strings: JSON re-encoding would hide
// changes to field order, escaped newlines, or whitespace in PVE responses.
// probeComment is an expected decoded value, not a captured response body.
const probeComment = "vault-wal:PROBECOMMENT12345"

const (
	probe1PermissionsResponse = `{"data":{"/access/realm/pve":{"Realm.AllocateUser":1,"User.Modify":1,"Sys.Audit":1},"/access/groups":{"Realm.AllocateUser":1,"User.Modify":1,"Sys.Audit":1}}}`

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
