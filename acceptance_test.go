// Package proxmox contains the Vault Proxmox VE secrets engine implementation.
//
// Acceptance tests in this file are gated by VAULT_ACC=1 and mutate a live
// operator-provided Proxmox VE 9.2.10 cluster. Password coverage is separately
// gated to the verified pve-manager/9.2.14 build. Provisioner rotation is
// additionally gated by PVE_ROTATE_ROOT_ACC=1 because it rotates a disposable
// provisioner identity created from the rotation-only bootstrap credentials.
// Required environment variables for the normal suite are PVE_ADDR,
// PVE_TOKEN_ID, PVE_TOKEN_SECRET, and PVE_TEST_GROUP. When rotation is opted
// in, TestAccRotateRoot uses PVE_ROTATE_BOOTSTRAP_TOKEN_ID,
// PVE_ROTATE_BOOTSTRAP_TOKEN_SECRET, and PVE_ROTATE_PROVISIONER_GROUP instead
// of the normal provisioner token.
// The test group must be pre-created and safely bound to a test-only role/path
// before running the suite. The authorization canary additionally requires
// PVE_BEHAVIORAL_PATH and PVE_BEHAVIORAL_MARKER so group-derived privilege is
// proven by response content, not by a bare 200 from /version. Operators must
// not edit vaultacc-* user comments while acceptance tests are running because
// WAL cleanup ownership relies on the vault-wal: comment marker.
package proxmox

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hazmei/vault-plugin-secrets-proxmox/internal/pveapi"
)

const (
	accRoleName               = "acc"
	accUserPrefix             = "vaultacc"
	accDefaultTTL             = 300
	accDefaultMaxTTL          = 900
	accBehaviorPathEnv        = "PVE_BEHAVIORAL_PATH"
	accBehaviorMarkerEnv      = "PVE_BEHAVIORAL_MARKER"
	accDefaultBehavior        = "/version"
	accTestTimeout            = 2 * time.Minute
	accPastExpireBuffer       = 60
	accDefaultWorkers         = 10
	accMaxWorkers             = 10
	accRotateRootEnv          = "PVE_ROTATE_ROOT_ACC"
	accRotateBootstrapID      = "PVE_ROTATE_BOOTSTRAP_TOKEN_ID"
	accRotateBootstrapSecret  = "PVE_ROTATE_BOOTSTRAP_TOKEN_SECRET"
	accRotateProvisionerGroup = "PVE_ROTATE_PROVISIONER_GROUP"
)

type accEnv struct {
	Address                 string
	TokenID                 string
	TokenSecret             string
	Group                   string
	CACert                  string
	TLSSkipVerify           bool
	BehaviorPath            string
	BehaviorMethod          string
	BehaviorMarker          string
	NegativePath            string
	NegativeMethod          string
	ACLCanaryPath           string
	ACLCanaryRole           string
	ACLCanaryTargetUser     string
	InsufficientTokenID     string
	InsufficientTokenSecret string
}

type accHarness struct {
	Env     accEnv
	Backend *backend
	Storage logical.Storage
	Client  pveapi.Client
}

type accHTTPClient struct {
	baseURL string
	http    *http.Client
}

func TestAccLifecycle(t *testing.T) {
	h := newAccHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), accTestTimeout)
	defer cancel()

	writeAccConfig(t, ctx, h)
	writeAccRole(t, ctx, h)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), accTestTimeout)
		defer cleanupCancel()
		rollbackRemainingAccWAL(t, cleanupCtx, h)
	})
	issued := issueAccCreds(t, ctx, h)

	registerAccUserCleanup(t, h.Client, issued.UserID)

	assertAccVersionSmoke(t, ctx, h.Env, issued.TokenID, issued.TokenSecret)

	renewed := renewAccSecret(t, ctx, h, issued.Secret, 120*time.Second)
	if renewed.Secret == nil || renewed.Secret.TTL <= 0 {
		t.Fatalf("renewal returned invalid secret metadata")
	}
	assertAccUserInGroup(t, ctx, h.Client, issued.UserID, h.Env.Group)

	revokeAccSecret(t, ctx, h, issued.Secret)
	assertAccUserMissing(t, ctx, h.Client, issued.UserID)
	revokeAccSecret(t, ctx, h, issued.Secret)
}

func TestAccAuthorizationContractCanary(t *testing.T) {
	h := newAccHarness(t)
	requireAccBehavioralCanaryEnv(t, h.Env)
	ctx, cancel := context.WithTimeout(context.Background(), accTestTimeout)
	defer cancel()

	writeAccConfig(t, ctx, h)
	writeAccRole(t, ctx, h)
	issued := issueAccCreds(t, ctx, h)
	registerAccUserCleanup(t, h.Client, issued.UserID)

	t.Run("direct ACL anti-privilege-escalation", func(t *testing.T) {
		assertAccAntiPrivilegeEscalation(t, ctx, h.Env)
	})
	t.Run("positive behavioral endpoint", func(t *testing.T) {
		assertAccPositiveBehavior(t, ctx, h.Env, issued.TokenID, issued.TokenSecret)
	})
	t.Run("negative authorization endpoint", func(t *testing.T) {
		assertAccNegativeAuthorization(t, ctx, h.Env, issued.TokenID, issued.TokenSecret)
	})

	pastExpire := time.Now().Unix() - accPastExpireBuffer
	if err := h.Client.UpdateUser(ctx, pveapi.UpdateUserRequest{UserID: issued.UserID, Expire: pastExpire, Groups: h.Env.Group, Enable: true, Append: true}); err != nil {
		t.Fatalf("expire issued user in the past: %v", err)
	}
	assertAccTokenStatus(t, ctx, h.Env, issued.TokenID, issued.TokenSecret, http.MethodGet, "/version", http.StatusUnauthorized)

	futureExpire := time.Now().Add(10 * time.Minute).Unix()
	if err := h.Client.UpdateUser(ctx, pveapi.UpdateUserRequest{UserID: issued.UserID, Expire: futureExpire, Groups: h.Env.Group, Enable: true, Append: true}); err != nil {
		t.Fatalf("restore issued user expiry: %v", err)
	}
	issued.Secret.IssueTime = time.Now().Add(-30 * time.Second)
	renewAccSecret(t, ctx, h, issued.Secret, 120*time.Second)
	assertAccUserInGroup(t, ctx, h.Client, issued.UserID, h.Env.Group)
	assertAccPositiveBehavior(t, ctx, h.Env, issued.TokenID, issued.TokenSecret)

	controlUser := accUserID(t, "fullreplace")
	createAccUser(t, ctx, h.Client, controlUser, h.Env.Group, futureExpire, walCommentPrefix+"fullreplace")
	registerAccUserCleanup(t, h.Client, controlUser)
	assertAccUserInGroup(t, ctx, h.Client, controlUser, h.Env.Group)
	raw := newAccHTTPClient(t, h.Env)
	form := accFullReplaceControlForm(time.Now().Add(20 * time.Minute))
	status, body, err := raw.do(ctx, http.MethodPut, "/access/users/"+url.PathEscape(controlUser), h.Env.TokenID, h.Env.TokenSecret, form)
	if err != nil {
		t.Fatalf("explicit replacement PUT control failed: %v", err)
	}
	if status < 200 || status >= 300 {
		t.Fatalf("explicit replacement PUT control status=%d body=%s", status, redactBody(body))
	}
	info, err := h.Client.GetUser(ctx, controlUser)
	if err != nil {
		t.Fatalf("read control user after explicit replacement PUT: %v", err)
	}
	if len(info.Groups) != 0 {
		t.Fatalf("explicit replacement PUT control groups=%v; want empty groups to confirm full-replace behavior", info.Groups)
	}
}

func TestAccRevocationIdempotencyAfterOutOfBandDelete(t *testing.T) {
	h := newAccHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), accTestTimeout)
	defer cancel()

	writeAccConfig(t, ctx, h)
	writeAccRole(t, ctx, h)
	issued := issueAccCreds(t, ctx, h)
	registerAccUserCleanup(t, h.Client, issued.UserID)
	deleteAccUser(t, ctx, h.Client, issued.UserID)
	assertAccUserMissing(t, ctx, h.Client, issued.UserID)
	revokeAccSecret(t, ctx, h, issued.Secret)
}

func TestAccInsufficientPrivileges(t *testing.T) {
	h := newAccHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), accTestTimeout)
	defer cancel()

	if h.Env.InsufficientTokenID == "" || h.Env.InsufficientTokenSecret == "" {
		t.Skip("optional insufficient-privilege test skipped: set PVE_INSUFFICIENT_TOKEN_ID and PVE_INSUFFICIENT_TOKEN_SECRET")
	}

	insufficient := h.Env
	insufficient.TokenID = h.Env.InsufficientTokenID
	insufficient.TokenSecret = h.Env.InsufficientTokenSecret
	assertAccTokenStatus(t, ctx, insufficient, insufficient.TokenID, insufficient.TokenSecret, http.MethodGet, "/version", http.StatusOK)

	b, storage := newAccBackend(t)
	resp, err := writeAccConfigWithEnv(ctx, b, storage, insufficient)
	if err != nil {
		t.Fatalf("insufficient config request returned framework error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected insufficient PVE token to be rejected by config validation")
	}
	if !isAccInsufficientPrivilegeError(resp.Error().Error()) {
		t.Fatalf("expected clear privilege/permission validation error, got: %s", resp.Error())
	}
}

func TestInsufficientPrivilegeErrorFragments(t *testing.T) {
	cases := []string{
		"admin token lacks User.Modify at /access/groups (or an ancestor with propagate=1)",
		"admin token lacks Sys.Audit at /access/groups (or an ancestor with propagate=1)",
		"admin token has an empty permission tree — this almost always means the token was " +
			"created with privsep=1 (the PVE default), which gives the token its own empty ACL " +
			"and inherits nothing from its user account; " +
			"fix: recreate the token with --privsep 0, e.g. " +
			"\"pveum user token add <user> <tokenid> --privsep 0\"",
		"PVE returned 403 on GET /access/permissions — token lacks required privileges",
	}
	for _, tc := range cases {
		if !isAccInsufficientPrivilegeError(tc) {
			t.Fatalf("isAccInsufficientPrivilegeError(%q) = false; want true", tc)
		}
	}
}

func TestFullReplaceControlFormSendsExplicitAppendZeroAndEmptyGroups(t *testing.T) {
	expire := time.Unix(1234, 0)

	form := accFullReplaceControlForm(expire)

	if got := form.Get("expire"); got != "1234" {
		t.Fatalf("expire=%q; want 1234", got)
	}
	if got := form.Get("append"); got != "0" {
		t.Fatalf("append=%q; want explicit 0", got)
	}
	groups, ok := form["groups"]
	if !ok {
		t.Fatal("groups field missing from full-replace control form")
	}
	if len(groups) != 1 || groups[0] != "" {
		t.Fatalf("groups=%v; want one empty groups field", groups)
	}
}

func accFullReplaceControlForm(expire time.Time) url.Values {
	return url.Values{
		"expire": {strconv.FormatInt(expire.Unix(), 10)},
		"append": {"0"},
		"groups": {""},
	}
}

func isAccInsufficientPrivilegeError(message string) bool {
	text := strings.ToLower(message)
	fragments := []string{
		"lacks user.modify",
		"lacks sys.audit",
		"privilege",
		"permission",
	}
	for _, fragment := range fragments {
		if strings.Contains(text, fragment) {
			return true
		}
	}
	return false
}

func TestAccWALRollback(t *testing.T) {
	h := newAccHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), accTestTimeout)
	defer cancel()

	writeAccConfig(t, ctx, h)
	userid := accUserID(t, "wal")
	nonce := walCommentPrefix + "acceptance"
	createAccUser(t, ctx, h.Client, userid, h.Env.Group, time.Now().Add(10*time.Minute).Unix(), nonce)
	registerAccUserCleanup(t, h.Client, userid)

	walID, err := framework.PutWAL(ctx, h.Storage, walTypeUser, walUser{UserID: userid, Nonce: nonce})
	if err != nil {
		t.Fatalf("PutWAL: %v", err)
	}
	entry, err := framework.GetWAL(ctx, h.Storage, walID)
	if err != nil {
		t.Fatalf("GetWAL: %v", err)
	}
	if entry == nil {
		t.Fatalf("GetWAL(%q) returned nil", walID)
		return
	}
	req := &logical.Request{Storage: h.Storage}
	if err := h.Backend.walRollback(ctx, req, entry.Kind, entry.Data); err != nil {
		t.Fatalf("walRollback: %v", err)
	}
	if err := framework.DeleteWAL(ctx, h.Storage, walID); err != nil {
		t.Fatalf("DeleteWAL after direct rollback: %v", err)
	}
	assertAccUserMissing(t, ctx, h.Client, userid)
}

func TestAccConcurrentIssuance(t *testing.T) {
	h := newAccHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	writeAccConfig(t, ctx, h)
	writeAccRole(t, ctx, h)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), accTestTimeout)
		defer cleanupCancel()
		rollbackRemainingAccWAL(t, cleanupCtx, h)
	})

	workers := accConcurrentWorkers(t)
	var wg sync.WaitGroup
	results := make(chan accIssuedCred, workers)
	errs := make(chan error, workers)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			issued, err := issueAccCredsE(ctx, h)
			if err != nil {
				errs <- err
				return
			}
			results <- issued
		}()
	}
	wg.Wait()
	close(results)
	close(errs)

	seen := make(map[string]struct{})
	var issued []accIssuedCred
	for res := range results {
		issued = append(issued, res)
		registerAccUserCleanup(t, h.Client, res.UserID)
		if _, ok := seen[res.UserID]; ok {
			t.Fatalf("duplicate userid issued concurrently: %s", res.UserID)
		}
		seen[res.UserID] = struct{}{}
	}
	for _, res := range issued {
		revokeAccSecret(t, ctx, h, res.Secret)
		assertAccUserMissing(t, ctx, h.Client, res.UserID)
	}
	rollbackRemainingAccWAL(t, ctx, h)

	var errMsgs []string
	for err := range errs {
		errMsgs = append(errMsgs, err.Error())
	}
	if len(errMsgs) > 0 {
		t.Fatalf("%d/%d concurrent issuances failed; lower PVE_CONCURRENT_WORKERS only if the test cluster cannot safely sustain default load: %s", len(errMsgs), workers, strings.Join(errMsgs, "; "))
	}
	if len(issued) != workers {
		t.Fatalf("issued %d credentials; want %d", len(issued), workers)
	}
}

func TestAccDeleteConfigGuard(t *testing.T) {
	h := newAccHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), accTestTimeout)
	defer cancel()

	writeAccConfig(t, ctx, h)
	resp, err := h.Backend.HandleRequest(ctx, &logical.Request{Operation: logical.DeleteOperation, Path: "config", Storage: h.Storage})
	if err != nil {
		t.Fatalf("delete config without force returned framework error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("delete config without force should return an error response")
	}
	resp, err = h.Backend.HandleRequest(ctx, &logical.Request{Operation: logical.DeleteOperation, Path: "config", Storage: h.Storage, Data: map[string]interface{}{"force": true}})
	if err != nil {
		t.Fatalf("delete config with force: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("delete config with force returned error response: %s", resp.Error())
	}
	readResp, err := h.Backend.HandleRequest(ctx, &logical.Request{Operation: logical.ReadOperation, Path: "config", Storage: h.Storage})
	if err != nil {
		t.Fatalf("read config after force delete: %v", err)
	}
	if readResp != nil {
		t.Fatalf("config still present after force delete: %#v", readResp.Data)
	}
}

type accIssuedCred struct {
	UserID      string
	TokenID     string
	TokenSecret string
	Secret      *logical.Secret
}

func newAccHarness(t *testing.T) accHarness {
	t.Helper()
	env := requireAccEnv(t)
	b, storage := newAccBackend(t)
	client := newPVEClient(t, env)
	return accHarness{Env: env, Backend: b, Storage: storage, Client: client}
}

func newAccBackend(t *testing.T) (*backend, logical.Storage) {
	t.Helper()
	conf := logical.TestBackendConfig()
	conf.StorageView = &logical.InmemStorage{}
	b, err := newBackend(context.Background(), conf)
	if err != nil {
		t.Fatalf("newBackend: %v", err)
	}
	return b, conf.StorageView
}

func requireAccEnv(t *testing.T) accEnv {
	t.Helper()
	if os.Getenv("VAULT_ACC") != "1" {
		t.Skip("acceptance tests require VAULT_ACC=1")
	}
	missing := requiredMissing("PVE_ADDR", "PVE_TOKEN_ID", "PVE_TOKEN_SECRET", "PVE_TEST_GROUP")
	if len(missing) > 0 {
		t.Skipf("acceptance tests require environment variables: %s", strings.Join(missing, ", "))
	}
	skipVerify, err := strconv.ParseBool(envDefault("PVE_TLS_SKIP_VERIFY", "false"))
	if err != nil {
		t.Fatalf("PVE_TLS_SKIP_VERIFY must parse as bool: %v", err)
	}
	behaviorPath := envDefault(accBehaviorPathEnv, accDefaultBehavior)
	behaviorMarker := os.Getenv(accBehaviorMarkerEnv)
	return accEnv{
		Address:                 os.Getenv("PVE_ADDR"),
		TokenID:                 os.Getenv("PVE_TOKEN_ID"),
		TokenSecret:             os.Getenv("PVE_TOKEN_SECRET"),
		Group:                   os.Getenv("PVE_TEST_GROUP"),
		CACert:                  os.Getenv("PVE_CA_CERT"),
		TLSSkipVerify:           skipVerify,
		BehaviorPath:            behaviorPath,
		BehaviorMethod:          strings.ToUpper(envDefault("PVE_BEHAVIORAL_METHOD", http.MethodGet)),
		BehaviorMarker:          behaviorMarker,
		NegativePath:            os.Getenv("PVE_NEGATIVE_AUTH_PATH"),
		NegativeMethod:          strings.ToUpper(envDefault("PVE_NEGATIVE_AUTH_METHOD", http.MethodGet)),
		ACLCanaryPath:           os.Getenv("PVE_ACL_CANARY_PATH"),
		ACLCanaryRole:           os.Getenv("PVE_ACL_CANARY_UNHELD_ROLE"),
		ACLCanaryTargetUser:     os.Getenv("PVE_ACL_CANARY_TARGET_USER"),
		InsufficientTokenID:     os.Getenv("PVE_INSUFFICIENT_TOKEN_ID"),
		InsufficientTokenSecret: os.Getenv("PVE_INSUFFICIENT_TOKEN_SECRET"),
	}
}

func requireRotateAccEnv(t *testing.T) accEnv {
	t.Helper()
	if os.Getenv("VAULT_ACC") != "1" {
		t.Skip("acceptance tests require VAULT_ACC=1")
	}
	if os.Getenv(accRotateRootEnv) != "1" {
		t.Skipf("rotate-root acceptance test skipped: set %s=1 to opt in", accRotateRootEnv)
	}
	missing := requiredMissing("PVE_ADDR", "PVE_TEST_GROUP", accRotateBootstrapID, accRotateBootstrapSecret, accRotateProvisionerGroup)
	if len(missing) > 0 {
		t.Skipf("rotate-root acceptance test requires environment variables: %s", strings.Join(missing, ", "))
	}
	skipVerify, err := strconv.ParseBool(envDefault("PVE_TLS_SKIP_VERIFY", "false"))
	if err != nil {
		t.Fatalf("PVE_TLS_SKIP_VERIFY must parse as bool: %v", err)
	}
	return accEnv{
		Address:       os.Getenv("PVE_ADDR"),
		Group:         os.Getenv("PVE_TEST_GROUP"),
		CACert:        os.Getenv("PVE_CA_CERT"),
		TLSSkipVerify: skipVerify,
	}
}

func TestValidateAccBehaviorEnvRequiresMarkerForCustomPath(t *testing.T) {
	err := validateAccBehavioralCanaryEnv(accEnv{BehaviorPath: "/nodes"})
	if err == nil {
		t.Fatal("expected PVE_BEHAVIORAL_PATH without marker to fail")
		return
	}
	if !strings.Contains(err.Error(), accBehaviorMarkerEnv) || !strings.Contains(err.Error(), "TestAccAuthorizationContractCanary") {
		t.Fatalf("validation error = %q; want marker and canary context", err.Error())
	}
}

func TestValidateAccBehaviorEnvRequiresPathForMarker(t *testing.T) {
	err := validateAccBehavioralCanaryEnv(accEnv{BehaviorMarker: "marker"})
	if err == nil {
		t.Fatal("expected PVE_BEHAVIORAL_MARKER without path to fail")
		return
	}
	if !strings.Contains(err.Error(), accBehaviorPathEnv) {
		t.Fatalf("validation error = %q; want behavioral path", err.Error())
	}
}

func TestValidateAccBehaviorEnvRejectsVersionSentinelWithSpecificMessage(t *testing.T) {
	err := validateAccBehavioralCanaryEnv(accEnv{BehaviorPath: accDefaultBehavior})
	if err == nil {
		t.Fatal("expected /version behavioral path sentinel to fail")
		return
	}
	want := "TestAccAuthorizationContractCanary requires PVE_BEHAVIORAL_PATH to be a group-role-gated endpoint, not /version and PVE_BEHAVIORAL_MARKER so group-derived privilege is proven by a behavioral endpoint response marker"
	if err.Error() != want {
		t.Fatalf("validation error = %q; want %q", err.Error(), want)
	}
	if !strings.Contains(err.Error(), "to be a group-role-gated endpoint, not /version") {
		t.Fatalf("validation error = %q; want /version-specific guidance", err.Error())
	}
	if !strings.Contains(err.Error(), accBehaviorMarkerEnv) {
		t.Fatalf("validation error = %q; want missing marker reported with /version path", err.Error())
	}
}

func requireAccBehavioralCanaryEnv(t *testing.T, env accEnv) {
	t.Helper()
	if err := validateAccBehavioralCanaryEnv(env); err != nil {
		t.Fatal(err)
	}
}

func validateAccBehavioralCanaryEnv(env accEnv) error {
	missing := []string{}
	switch env.BehaviorPath {
	case accDefaultBehavior:
		missing = append(missing, accBehaviorPathEnv+" to be a group-role-gated endpoint, not /version")
	case "":
		missing = append(missing, accBehaviorPathEnv)
	}
	if env.BehaviorMarker == "" {
		missing = append(missing, accBehaviorMarkerEnv)
	}
	if len(missing) > 0 {
		return fmt.Errorf("TestAccAuthorizationContractCanary requires %s so group-derived privilege is proven by a behavioral endpoint response marker", strings.Join(missing, " and "))
	}
	return nil
}

func accConcurrentWorkers(t *testing.T) int {
	t.Helper()
	raw := envDefault("PVE_CONCURRENT_WORKERS", strconv.Itoa(accDefaultWorkers))
	workers, err := strconv.Atoi(raw)
	if err != nil || workers < 1 || workers > accMaxWorkers {
		t.Fatalf("PVE_CONCURRENT_WORKERS must be an integer in [1,%d], got %q", accMaxWorkers, raw)
	}
	return workers
}

func requiredMissing(names ...string) []string {
	var missing []string
	for _, name := range names {
		if os.Getenv(name) == "" {
			missing = append(missing, name)
		}
	}
	return missing
}

func envDefault(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func newPVEClient(t *testing.T, env accEnv) pveapi.Client {
	t.Helper()
	client, err := pveapi.NewClient(pveapi.ClientConfig{Address: env.Address, TokenID: env.TokenID, TokenSecret: env.TokenSecret, TLSSkipVerify: env.TLSSkipVerify, CACert: env.CACert})
	if err != nil {
		t.Fatalf("new PVE client: %v", err)
	}
	return client
}

func writeAccConfig(t *testing.T, ctx context.Context, h accHarness) {
	t.Helper()
	resp, err := writeAccConfigWithEnv(ctx, h.Backend, h.Storage, h.Env)
	if err != nil {
		t.Fatalf("write config: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("write config error response: %s", resp.Error())
	}
}

func writeAccConfigWithEnv(ctx context.Context, b *backend, storage logical.Storage, env accEnv) (*logical.Response, error) {
	return b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"address":         env.Address,
			"token_id":        env.TokenID,
			"token_secret":    env.TokenSecret,
			"tls_skip_verify": env.TLSSkipVerify,
			"ca_cert":         env.CACert,
			"default_ttl":     accDefaultTTL,
			"default_max_ttl": accDefaultMaxTTL,
		},
	})
}

func writeAccRole(t *testing.T, ctx context.Context, h accHarness) {
	t.Helper()
	writeAccRoleNamed(t, ctx, h, accRoleName, modeToken)
}

func writeAccRoleNamed(t *testing.T, ctx context.Context, h accHarness, roleName, mode string) {
	t.Helper()
	resp, err := h.Backend.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/" + roleName,
		Storage:   h.Storage,
		Data: map[string]interface{}{
			"group":       h.Env.Group,
			"user_prefix": accUserPrefix,
			"realm":       "pve",
			"ttl":         accDefaultTTL,
			"max_ttl":     accDefaultMaxTTL,
			"mode":        mode,
		},
	})
	if err != nil {
		t.Fatalf("write role: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("write role error response: %s", resp.Error())
	}
}

func issueAccCreds(t *testing.T, ctx context.Context, h accHarness) accIssuedCred {
	t.Helper()
	issued, err := issueAccCredsE(ctx, h)
	if err != nil {
		t.Fatalf("issue creds: %v", err)
	}
	return issued
}

func issueAccCredsE(ctx context.Context, h accHarness) (accIssuedCred, error) {
	resp, err := h.Backend.HandleRequest(ctx, &logical.Request{Operation: logical.ReadOperation, Path: "creds/" + accRoleName, Storage: h.Storage})
	if err != nil {
		return accIssuedCred{}, err
	}
	if resp == nil || resp.IsError() || resp.Secret == nil {
		return accIssuedCred{}, fmt.Errorf("credential response failed: %v", responseErr(resp))
	}
	userID, _ := resp.Data["user_id"].(string)
	tokenID, _ := resp.Data["token_id"].(string)
	tokenSecret, _ := resp.Data["token_secret"].(string)
	if userID == "" || tokenID == "" || tokenSecret == "" {
		return accIssuedCred{}, fmt.Errorf("credential response missing user_id/token_id/token_secret")
	}
	if !strings.HasSuffix(tokenID, "!"+leaseTokenID) {
		return accIssuedCred{}, fmt.Errorf("token_id suffix mismatch for %q", tokenID)
	}
	resp.Secret.IssueTime = time.Now()
	return accIssuedCred{UserID: userID, TokenID: tokenID, TokenSecret: tokenSecret, Secret: resp.Secret}, nil
}

func responseErr(resp *logical.Response) error {
	if resp == nil {
		return errors.New("nil response")
	}
	if resp.IsError() {
		return resp.Error()
	}
	return errors.New("nil secret")
}

func renewAccSecret(t *testing.T, ctx context.Context, h accHarness, secret *logical.Secret, increment time.Duration) *logical.Response {
	return renewAccSecretNamed(t, ctx, h, accRoleName, secret, increment)
}

func renewAccSecretNamed(t *testing.T, ctx context.Context, h accHarness, roleName string, secret *logical.Secret, increment time.Duration) *logical.Response {
	t.Helper()
	secret.Increment = increment
	if secret.IssueTime.IsZero() {
		secret.IssueTime = time.Now()
	}
	req := logical.RenewRequest("creds/"+roleName, secret, nil)
	req.Storage = h.Storage
	resp, err := h.Backend.secretTokenRenew(ctx, req, nil)
	if err != nil {
		t.Fatalf("renew secret: %v", err)
	}
	return resp
}

func revokeAccSecret(t *testing.T, ctx context.Context, h accHarness, secret *logical.Secret) {
	revokeAccSecretNamed(t, ctx, h, accRoleName, secret)
}

func revokeAccSecretNamed(t *testing.T, ctx context.Context, h accHarness, roleName string, secret *logical.Secret) {
	t.Helper()
	req := logical.RevokeRequest("creds/"+roleName, secret, nil)
	req.Storage = h.Storage
	resp, err := h.Backend.secretTokenRevoke(ctx, req, nil)
	if err != nil {
		t.Fatalf("revoke secret: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("revoke returned error response: %s", resp.Error())
	}
}

func createAccUser(t *testing.T, ctx context.Context, client pveapi.Client, userid, group string, expire int64, comment string) {
	t.Helper()
	if err := client.CreateUser(ctx, pveapi.CreateUserRequest{UserID: userid, Groups: group, Expire: expire, Enable: true, Comment: comment}); err != nil {
		t.Fatalf("create PVE user %q: %v", userid, err)
	}
	assertAccUserInGroup(t, ctx, client, userid, group)
}

func registerAccUserCleanup(t *testing.T, client pveapi.Client, userid string) {
	t.Helper()
	if userid == "" {
		return
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		deleteAccUser(t, cleanupCtx, client, userid)
	})
}

func deleteAccUser(t *testing.T, ctx context.Context, client pveapi.Client, userid string) {
	t.Helper()
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if err := client.DeleteUser(ctx, userid); err != nil && !errors.Is(err, pveapi.ErrUserNotFound) {
			lastErr = err
			time.Sleep(time.Duration(attempt+1) * 200 * time.Millisecond)
			continue
		}
		_, err := client.GetUser(ctx, userid)
		if errors.Is(err, pveapi.ErrUserNotFound) {
			return
		}
		if err == nil {
			lastErr = fmt.Errorf("user %q still exists after DeleteUser returned success", userid)
		} else {
			lastErr = err
		}
		time.Sleep(time.Duration(attempt+1) * 200 * time.Millisecond)
	}
	t.Errorf("cleanup failed to confirm user %q deleted: %v", userid, lastErr)
}

func assertAccUserInGroup(t *testing.T, ctx context.Context, client pveapi.Client, userid, group string) {
	t.Helper()
	info, err := client.GetUser(ctx, userid)
	if err != nil {
		t.Fatalf("GetUser(%q): %v", userid, err)
	}
	if !containsGroup(info.Groups, group) {
		t.Fatalf("user %q groups=%v; want group %q", userid, info.Groups, group)
	}
}

func assertAccUserMissing(t *testing.T, ctx context.Context, client pveapi.Client, userid string) {
	t.Helper()
	_, err := client.GetUser(ctx, userid)
	if !errors.Is(err, pveapi.ErrUserNotFound) {
		t.Fatalf("GetUser(%q) err=%v; want ErrUserNotFound", userid, err)
	}
}

func rollbackRemainingAccWAL(t *testing.T, ctx context.Context, h accHarness) {
	t.Helper()
	ids, err := framework.ListWAL(ctx, h.Storage)
	if err != nil {
		t.Fatalf("ListWAL after concurrent issuance: %v", err)
	}
	for _, id := range ids {
		entry, getErr := framework.GetWAL(ctx, h.Storage, id)
		if getErr != nil {
			t.Fatalf("GetWAL(%q): %v", id, getErr)
		}
		if entry == nil {
			continue
		}
		if rollbackErr := h.Backend.walRollback(ctx, &logical.Request{Storage: h.Storage}, entry.Kind, entry.Data); rollbackErr != nil {
			t.Fatalf("walRollback(%q): %v", id, rollbackErr)
		}
		if delErr := framework.DeleteWAL(ctx, h.Storage, id); delErr != nil {
			t.Fatalf("DeleteWAL(%q): %v", id, delErr)
		}
	}
}

func accUserID(t *testing.T, label string) string {
	t.Helper()
	suffix, err := randomSuffix()
	if err != nil {
		t.Fatalf("random suffix: %v", err)
	}
	return buildUserID(accUserPrefix, label, suffix, "pve")
}

func newAccHTTPClient(t *testing.T, env accEnv) *accHTTPClient {
	t.Helper()
	tlsCfg := &tls.Config{InsecureSkipVerify: env.TLSSkipVerify} //nolint:gosec // acceptance env controls TLS mode.
	if env.CACert != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(env.CACert)) {
			t.Fatalf("parse PVE_CA_CERT PEM")
		}
		tlsCfg.RootCAs = pool
	}
	return &accHTTPClient{
		baseURL: strings.TrimRight(env.Address, "/") + "/api2/json",
		http:    &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}},
	}
}

func assertAccPositiveBehavior(t *testing.T, ctx context.Context, env accEnv, tokenID, tokenSecret string) {
	t.Helper()
	_, body := assertAccTokenStatus(t, ctx, env, tokenID, tokenSecret, env.BehaviorMethod, env.BehaviorPath, http.StatusOK)
	if env.BehaviorMarker == "" {
		t.Fatalf("%s is required for TestAccAuthorizationContractCanary", accBehaviorMarkerEnv)
	}
	if !strings.Contains(string(body), env.BehaviorMarker) {
		t.Fatalf("positive behavior endpoint %s %s response did not contain PVE_BEHAVIORAL_MARKER %q; body=%s", env.BehaviorMethod, env.BehaviorPath, env.BehaviorMarker, redactBody(body))
	}
}

func assertAccVersionSmoke(t *testing.T, ctx context.Context, env accEnv, tokenID, tokenSecret string) {
	t.Helper()
	assertAccTokenStatus(t, ctx, env, tokenID, tokenSecret, http.MethodGet, accDefaultBehavior, http.StatusOK)
}

func assertAccNegativeAuthorization(t *testing.T, ctx context.Context, env accEnv, tokenID, tokenSecret string) {
	t.Helper()
	if env.NegativePath == "" {
		t.Skip("negative authorization endpoint skipped: set PVE_NEGATIVE_AUTH_PATH and optionally PVE_NEGATIVE_AUTH_METHOD")
	}
	assertAccTokenStatus(t, ctx, env, tokenID, tokenSecret, env.NegativeMethod, env.NegativePath, http.StatusForbidden)
}

func assertAccAntiPrivilegeEscalation(t *testing.T, ctx context.Context, env accEnv) {
	t.Helper()
	missing := []string{}
	if env.ACLCanaryPath == "" {
		missing = append(missing, "PVE_ACL_CANARY_PATH")
	}
	if env.ACLCanaryRole == "" {
		missing = append(missing, "PVE_ACL_CANARY_UNHELD_ROLE")
	}
	if env.ACLCanaryTargetUser == "" {
		missing = append(missing, "PVE_ACL_CANARY_TARGET_USER")
	}
	if len(missing) > 0 {
		t.Skipf("direct ACL anti-privilege-escalation canary skipped: configure %s for a non-full-admin token and an unheld role", strings.Join(missing, ", "))
	}
	client := newAccHTTPClient(t, env)
	form := url.Values{
		"path":      {env.ACLCanaryPath},
		"users":     {env.ACLCanaryTargetUser},
		"roles":     {env.ACLCanaryRole},
		"propagate": {"1"},
	}
	status, body, err := client.do(ctx, http.MethodPut, "/access/acl", env.TokenID, env.TokenSecret, form)
	if err != nil {
		t.Fatalf("direct ACL canary request failed: %v", err)
	}
	if status >= 200 && status < 300 {
		deleteForm := url.Values{
			"path":      {env.ACLCanaryPath},
			"users":     {env.ACLCanaryTargetUser},
			"roles":     {env.ACLCanaryRole},
			"propagate": {"1"},
			"delete":    {"1"},
		}
		cleanupStatus, cleanupBody, cleanupErr := client.do(ctx, http.MethodPut, "/access/acl", env.TokenID, env.TokenSecret, deleteForm)
		if cleanupErr != nil || cleanupStatus < 200 || cleanupStatus >= 300 {
			t.Fatalf("direct ACL canary unexpectedly succeeded and cleanup failed: status=%d cleanup_status=%d cleanup_err=%v body=%s cleanup_body=%s", status, cleanupStatus, cleanupErr, redactBody(body), redactBody(cleanupBody))
		}
	}
	if status != http.StatusForbidden {
		t.Fatalf("direct ACL canary status=%d; want 403 for unheld role with non-full-admin token body=%s", status, redactBody(body))
	}
}

func assertAccTokenStatus(t *testing.T, ctx context.Context, env accEnv, tokenID, tokenSecret, method, path string, want int) (int, []byte) {
	t.Helper()
	client := newAccHTTPClient(t, env)
	status, body, err := client.do(ctx, method, path, tokenID, tokenSecret, nil)
	if err != nil {
		t.Fatalf("token request %s %s: %v", method, path, err)
	}
	if status != want {
		t.Fatalf("token request %s %s status=%d; want %d", method, path, status, want)
	}
	return status, body
}

func (c *accHTTPClient) do(ctx context.Context, method, path, tokenID, tokenSecret string, form url.Values) (int, []byte, error) {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "PVEAPIToken="+tokenID+"="+tokenSecret)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close() //nolint:errcheck // test helper; close errors are not actionable.
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, respBody, nil
}

func redactBody(body []byte) string {
	text := strings.TrimSpace(string(body))
	if len(text) > 256 {
		return text[:256] + "..."
	}
	return text
}

// accPasswordRoleName is the role used by the opt-in password acceptance test.
// It is separate from accRoleName so a password run cannot disturb the
// token-mode role the required acceptance tests depend on.
const accPasswordRoleName = "acc-password-role"

// accPasswordEnv gates the password acceptance test. Password credentials are
// only exercised against a realm with recorded P0 evidence (docs/PVE_PROBES.md:
// the `pve` realm), and only when the operator explicitly opts in — the test
// creates a password-authenticating PVE user on the target.
const accPasswordEnv = "PVE_PASSWORD_ACC"

// TestAccPasswordLifecycle is the opt-in live coverage required by
// docs/IMPLEMENTATION_PLAN.md P6 for password mode: issuance, authentication,
// confirmed absence of any API token, renewal preserving the ORIGINAL password,
// the expiry backstop, disablement, and deletion on revoke.
//
// Gated by VAULT_ACC=1 (like every TestAcc*), PVE_PASSWORD_ACC=1, and the exact
// verified pve-manager/9.2.14/a1480fa6b8d899cb build precondition. Non-verified
// builds skip this test because password behavior is not verified there. It
// never prints a password: every assertion reports status codes only.
func TestAccPasswordLifecycle(t *testing.T) {
	h := newAccHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), accTestTimeout)
	defer cancel()

	if os.Getenv(accPasswordEnv) != "1" {
		t.Skipf("password acceptance test skipped: set %s=1 to opt in (creates a password-authenticating PVE user)", accPasswordEnv)
	}
	info, err := h.Client.GetVersionInfo(ctx)
	if err != nil {
		t.Fatalf("verify password acceptance PVE build: %v", err)
	}
	if info.Version != passwordVerifiedVersion || info.RepoID != passwordVerifiedRepoID {
		t.Skipf(
			"password mode requires verified PVE build %s; this cluster reports version=%q repoid=%q (docs/PVE_PROBES.md Probe P0 records password behavior only on the verified build)",
			passwordVerifiedBuild, info.Version, info.RepoID,
		)
	}

	writeAccConfig(t, ctx, h)
	writeAccRoleNamed(t, ctx, h, accPasswordRoleName, modePassword)

	resp, err := h.Backend.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/" + accPasswordRoleName,
		Storage:   h.Storage,
	})
	if err != nil {
		t.Fatalf("issue password creds: %v", err)
	}
	if resp == nil || resp.IsError() || resp.Secret == nil {
		t.Fatalf("password credential response failed: %v", responseErr(resp))
	}
	userID, _ := resp.Data["user_id"].(string)
	password, _ := resp.Data["password"].(string)
	if userID == "" || password == "" {
		t.Fatal("password credential response missing user_id or password")
	}
	if _, present := resp.Data["token_id"]; present {
		t.Error("password credential response must not contain token_id")
	}
	registerAccUserCleanup(t, h.Client, userID)
	resp.Secret.IssueTime = time.Now()

	assertAccUserInGroup(t, ctx, h.Client, userID, h.Env.Group)

	// The password authenticates.
	assertAccTicketStatus(t, ctx, h.Env, userID, password, http.StatusOK)

	// No API token was minted on this user.
	raw := newAccHTTPClient(t, h.Env)
	status, body, err := raw.do(ctx, http.MethodGet, "/access/users/"+url.PathEscape(userID)+"/token", h.Env.TokenID, h.Env.TokenSecret, nil)
	if err != nil {
		t.Fatalf("list tokens for password user: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("list tokens status=%d body=%s", status, redactBody(body))
	}
	if strings.Contains(string(body), `"tokenid"`) {
		t.Errorf("password mode must mint no API token; token list body=%s", redactBody(body))
	}

	// Renewal extends expiry and the ORIGINAL password still authenticates
	// (PVE_PROBES.md Probe P0, 28 Aug 2026).
	renewAccSecret(t, ctx, h, resp.Secret, 120*time.Second)
	assertAccUserInGroup(t, ctx, h.Client, userID, h.Env.Group)
	assertAccTicketStatus(t, ctx, h.Env, userID, password, http.StatusOK)

	// Expiry backstop: an expire in the past rejects authentication.
	pastExpire := time.Now().Unix() - accPastExpireBuffer
	if expireErr := h.Client.UpdateUser(ctx, pveapi.UpdateUserRequest{UserID: userID, Expire: pastExpire, Groups: h.Env.Group, Enable: true, Append: true}); expireErr != nil {
		t.Fatalf("expire password user in the past: %v", expireErr)
	}
	assertAccTicketStatus(t, ctx, h.Env, userID, password, http.StatusUnauthorized)

	futureExpire := time.Now().Add(10 * time.Minute).Unix()
	if restoreErr := h.Client.UpdateUser(ctx, pveapi.UpdateUserRequest{UserID: userID, Expire: futureExpire, Groups: h.Env.Group, Enable: true, Append: true}); restoreErr != nil {
		t.Fatalf("restore password user expiry: %v", restoreErr)
	}
	assertAccTicketStatus(t, ctx, h.Env, userID, password, http.StatusOK)

	// Disablement: enable=0 rejects authentication. Sent as a raw PUT because
	// UpdateUserRequest.Validate deliberately refuses to build a disabling
	// renewal request.
	disable := url.Values{}
	disable.Set("expire", fmt.Sprintf("%d", futureExpire))
	disable.Set("groups", h.Env.Group)
	disable.Set("enable", "0")
	disable.Set("append", "1")
	status, body, err = raw.do(ctx, http.MethodPut, "/access/users/"+url.PathEscape(userID), h.Env.TokenID, h.Env.TokenSecret, disable)
	if err != nil {
		t.Fatalf("disable password user: %v", err)
	}
	if status < 200 || status >= 300 {
		t.Fatalf("disable password user status=%d body=%s", status, redactBody(body))
	}
	assertAccTicketStatus(t, ctx, h.Env, userID, password, http.StatusUnauthorized)

	// Revocation deletes the user; authentication stays rejected.
	revokeReq := logical.RevokeRequest("creds/"+accPasswordRoleName, resp.Secret, nil)
	revokeReq.Storage = h.Storage
	if _, revokeErr := h.Backend.Secret(secretTypePassword).Revoke(ctx, revokeReq, nil); revokeErr != nil {
		t.Fatalf("revoke password secret: %v", revokeErr)
	}
	assertAccUserMissing(t, ctx, h.Client, userID)
	assertAccTicketStatus(t, ctx, h.Env, userID, password, http.StatusUnauthorized)
}

// TestAccRotateRoot exercises destructive provisioner-token rotation directly
// against the backend with isolated in-memory storage; it never starts Vault.
// The disposable provisioner token must be dedicated and exclusive to this test.
func TestAccRotateRoot(t *testing.T) {
	rotateEnv := requireRotateAccEnv(t)
	bootstrapEnv := rotateEnv
	bootstrapEnv.TokenID = os.Getenv(accRotateBootstrapID)
	bootstrapEnv.TokenSecret = os.Getenv(accRotateBootstrapSecret)
	bootstrapClient := newPVEClient(t, bootstrapEnv)
	ctx, cancel := context.WithTimeout(context.Background(), accTestTimeout)
	defer cancel()
	info, err := bootstrapClient.GetVersionInfo(ctx)
	if err != nil {
		t.Fatalf("verify rotate-root PVE build: %v", err)
	}
	if info.Version != passwordVerifiedVersion || info.RepoID != passwordVerifiedRepoID {
		t.Skipf("rotate-root acceptance test requires verified PVE build %s; target reports version=%q repoid=%q", passwordVerifiedBuild, info.Version, info.RepoID)
	}

	// This user is the only provisioner identity this test may rotate. Register
	// cleanup immediately after creation so every later failure removes it via
	// the bootstrap client; deleting the user also cascades its tokens.
	provisionerUser := accUserID(t, "rotate-provisioner")
	if createErr := bootstrapClient.CreateUser(ctx, pveapi.CreateUserRequest{
		UserID: provisionerUser,
		Groups: os.Getenv(accRotateProvisionerGroup),
		Expire: time.Now().Add(accTestTimeout).Unix(),
		Enable: true,
	}); createErr != nil {
		t.Fatalf("create disposable rotate provisioner user %q: %v", provisionerUser, createErr)
	}
	registerAccUserCleanup(t, bootstrapClient, provisionerUser)
	assertAccUserInGroup(t, ctx, bootstrapClient, provisionerUser, os.Getenv(accRotateProvisionerGroup))

	provisionerTokenID := provisionerUser + "!acceptance"
	provisionerTokenSecret, err := bootstrapClient.CreateToken(ctx, provisionerUser, "acceptance")
	if err != nil {
		t.Fatalf("create disposable rotate provisioner token: %v", err)
	}
	rotateEnv.TokenID = provisionerTokenID
	rotateEnv.TokenSecret = provisionerTokenSecret
	b, storage := newAccBackend(t)
	h := accHarness{Env: rotateEnv, Backend: b, Storage: storage, Client: newPVEClient(t, rotateEnv)}

	suffix, err := randomSuffix()
	if err != nil {
		t.Fatalf("generate isolated rotate-root role name: %v", err)
	}
	roleName := "acc-rotate-" + suffix
	writeAccConfig(t, ctx, h)
	writeAccRoleNamed(t, ctx, h, roleName, modePassword)

	oldTokenID, oldTokenSecret := h.Env.TokenID, h.Env.TokenSecret
	rotationResp, err := h.Backend.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "rotate-root",
		Storage:   h.Storage,
		Data: map[string]interface{}{
			"expected_token_id": oldTokenID,
			"confirm_exclusive": true,
		},
	})
	if err != nil {
		t.Fatalf("rotate-root request: %v", err)
	}
	if rotationResp == nil || rotationResp.IsError() {
		t.Fatalf("rotate-root returned an error response: %v", responseErr(rotationResp))
	}
	if rotationResp.Data["status"] != "rotated" {
		t.Fatalf("rotate-root status=%v; want rotated", rotationResp.Data["status"])
	}
	newTokenID, ok := rotationResp.Data["token_id"].(string)
	if !ok || newTokenID == "" || newTokenID == oldTokenID {
		t.Fatal("rotate-root returned an invalid replacement token ID")
	}
	oldOwner, _, err := splitTokenID(oldTokenID)
	if err != nil {
		t.Fatalf("parse configured token ID: %v", err)
	}
	newOwner, _, err := splitTokenID(newTokenID)
	if err != nil {
		t.Fatalf("parse replacement token ID: %v", err)
	}
	if newOwner != oldOwner {
		t.Fatal("replacement token owner changed")
	}
	assertAccNoSensitiveValues(t, rotationResp.Data, oldTokenSecret, "rotation response")

	configResp, err := h.Backend.HandleRequest(ctx, &logical.Request{Operation: logical.ReadOperation, Path: "config", Storage: h.Storage})
	if err != nil {
		t.Fatalf("read rotated config: %v", err)
	}
	if configResp == nil || configResp.IsError() {
		t.Fatalf("read rotated config returned an error response: %v", responseErr(configResp))
	}
	rotatedCfg, err := getConfig(ctx, h.Storage)
	if err != nil || rotatedCfg == nil || rotatedCfg.TokenSecret == "" {
		t.Fatal("rotated config did not retain a replacement token secret")
	}
	newTokenSecret := rotatedCfg.TokenSecret
	assertAccNoSensitiveValues(t, configResp.Data, oldTokenSecret, "config response")
	assertAccNoSensitiveValues(t, configResp.Data, newTokenSecret, "config response")
	assertAccNoSensitiveValues(t, rotationResp.Data, newTokenSecret, "rotation response")

	assertAccTokenStatus(t, ctx, h.Env, oldTokenID, oldTokenSecret, http.MethodGet, accDefaultBehavior, http.StatusUnauthorized)
	replacementEnv := h.Env
	replacementEnv.TokenID, replacementEnv.TokenSecret = newTokenID, newTokenSecret
	// The disposable provisioner client is intentionally dead after rotation.
	// Use the replacement for all subsequent PVE assertions.
	h.Client = newPVEClient(t, replacementEnv)
	issuedResp, err := h.Backend.HandleRequest(ctx, &logical.Request{Operation: logical.ReadOperation, Path: "creds/" + roleName, Storage: h.Storage})
	if err != nil {
		t.Fatalf("issue password credential with replacement token: %v", err)
	}
	if issuedResp == nil || issuedResp.IsError() || issuedResp.Secret == nil {
		t.Fatalf("replacement token could not issue password credential: %v", responseErr(issuedResp))
	}
	userID, _ := issuedResp.Data["user_id"].(string)
	password, _ := issuedResp.Data["password"].(string)
	if userID == "" || password == "" {
		t.Fatal("password credential response missing user_id or password")
	}
	// Register the exact lease user immediately; cleanup never deletes the
	// replacement provisioner token.
	registerAccUserCleanup(t, h.Client, userID)
	issuedResp.Secret.IssueTime = time.Now()

	assertAccUserInGroup(t, ctx, h.Client, userID, h.Env.Group)
	assertAccTicketStatus(t, ctx, replacementEnv, userID, password, http.StatusOK)
	assertAccNoAPIToken(t, ctx, replacementEnv, userID)
	renewAccSecretNamed(t, ctx, h, roleName, issuedResp.Secret, 120*time.Second)
	assertAccUserInGroup(t, ctx, h.Client, userID, h.Env.Group)
	assertAccTicketStatus(t, ctx, replacementEnv, userID, password, http.StatusOK)
	revokeAccSecretNamed(t, ctx, h, roleName, issuedResp.Secret)
	assertAccUserMissing(t, ctx, h.Client, userID)
	assertAccTicketStatus(t, ctx, replacementEnv, userID, password, http.StatusUnauthorized)
}

func assertAccNoSensitiveValues(t *testing.T, data map[string]interface{}, secret, contextName string) {
	t.Helper()
	if _, present := data["token_secret"]; present {
		t.Fatalf("%s must not contain token_secret", contextName)
	}
	for _, value := range data {
		if text, ok := value.(string); ok && secret != "" && strings.Contains(text, secret) {
			t.Fatalf("%s contains a sensitive token value", contextName)
		}
	}
}

func assertAccNoAPIToken(t *testing.T, ctx context.Context, env accEnv, userid string) {
	t.Helper()
	client := newAccHTTPClient(t, env)
	status, body, err := client.do(ctx, http.MethodGet, "/access/users/"+url.PathEscape(userid)+"/token", env.TokenID, env.TokenSecret, nil)
	if err != nil {
		t.Fatalf("list password-user tokens: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("list password-user tokens status=%d; want %d", status, http.StatusOK)
	}
	if strings.Contains(string(body), `"tokenid"`) {
		t.Fatal("password mode minted an API token")
	}
}

// assertAccTicketStatus posts credentials to /access/ticket and asserts the
// HTTP status. The password is sent in the form body and never logged.
func assertAccTicketStatus(t *testing.T, ctx context.Context, env accEnv, userID, password string, want int) {
	t.Helper()
	client := newAccHTTPClient(t, env)

	form := url.Values{}
	form.Set("username", userID)
	form.Set("password", password)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, client.baseURL+"/access/ticket", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build ticket request: %v", err)
	}
	// Deliberately unauthenticated: /access/ticket authenticates the supplied
	// credentials, so no admin Authorization header is sent.
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.http.Do(req)
	if err != nil {
		t.Fatalf("ticket request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // test helper; close errors are not actionable.
	_, err = io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read ticket response: %v", err)
	}
	if resp.StatusCode != want {
		t.Fatalf("ticket status=%d; want %d", resp.StatusCode, want)
	}
}
