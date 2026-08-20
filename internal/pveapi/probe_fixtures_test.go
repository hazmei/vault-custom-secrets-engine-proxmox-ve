package pveapi

import (
	"bytes"
	"encoding/json"
	"testing"
)

// These fixtures are copied byte-for-byte from the raw evidence blocks in
// docs/PVE_PROBES.md. Keep them as raw strings: JSON re-encoding would hide
// changes to field order, escaped newlines, or whitespace in PVE responses.
const (
	probe1PermissionsResponse = `{"data":{"/access/realm/pve":{"Realm.AllocateUser":1,"User.Modify":1,"Sys.Audit":1},"/access/groups":{"Realm.AllocateUser":1,"User.Modify":1,"Sys.Audit":1}}}`

	probe2DuplicateUserResponse    = `{"data":null,"message":"create user failed: user 'probe-dup-52445741@pve' already exists\n"}`
	probe3MissingUserResponse      = `{"data":null,"message":"no such user ('probe-ghost-nonexistent@pve')\n"}`
	probe4MissingUserResponse      = `{"data":null,"message":"no such user ('probe-ghost-nonexistent@pve')\n"}`
	probe5MissingGroupResponse     = `{"data":null,"message":"group 'definitely-not-a-real-group' does not exist\n"}`
	probe6EmptyPermissionsResponse = `{"data":{}}`
	probe6bDuplicateTokenResponse  = `{"message":"Parameter verification failed.\n","data":null,"errors":{"tokenid":"Token already exists."}}`

	groupAddUserResponse  = `{"data":{"enable":1,"expire":1786972261,"tokens":null,"groups":["vault-test-grp"]}}`
	groupAddGroupResponse = `{"data":{"comment":"Vault dynamic-cred test group","members":["probe-ga-7mqj5nzp@pve"]}}`

	renewalPreserveBeforeResponse = `{"data":{"tokens":null,"enable":1,"groups":["vault-test-grp"],"expire":1786986804}}`
	renewalPreserveAfterResponse  = `{"data":{"enable":1,"groups":["vault-test-grp"],"tokens":null,"expire":1786990429}}`
)

// TestProbeFixturesRemainRawJSON guards against accidental formatting changes
// such as re-encoding, CRLF conversion, or adding a newline to a fixture.
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
		{name: "Probe 6", body: probe6EmptyPermissionsResponse},
		{name: "Probe 6b", body: probe6bDuplicateTokenResponse},
		{name: "GROUPADD user", body: groupAddUserResponse},
		{name: "GROUPADD group", body: groupAddGroupResponse},
		{name: "RENEWAL-PRESERVE before", body: renewalPreserveBeforeResponse},
		{name: "RENEWAL-PRESERVE after", body: renewalPreserveAfterResponse},
	}

	for _, fixture := range fixtures {
		fixture := fixture
		t.Run(fixture.name, func(t *testing.T) {
			if !json.Valid([]byte(fixture.body)) {
				t.Fatal("fixture is not valid JSON")
			}
			if bytes.Contains([]byte(fixture.body), []byte("\r")) || bytes.Contains([]byte(fixture.body), []byte("\n")) {
				t.Fatal("fixture contains a literal line ending; preserve the documented bytes")
			}
		})
	}
}

func TestGroupAddGroupFixtureFields(t *testing.T) {
	t.Parallel()
	var response struct {
		Data struct {
			Comment string   `json:"comment"`
			Members []string `json:"members"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(groupAddGroupResponse), &response); err != nil {
		t.Fatalf("decode GROUPADD group response: %v", err)
	}
	if response.Data.Comment != "Vault dynamic-cred test group" {
		t.Errorf("comment = %q; want documented group comment", response.Data.Comment)
	}
	if len(response.Data.Members) != 1 || response.Data.Members[0] != "probe-ga-7mqj5nzp@pve" {
		t.Errorf("members = %#v; want documented probe user", response.Data.Members)
	}
}
