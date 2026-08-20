// Package proxmox contains the Vault Proxmox VE secrets engine implementation.
//
// Acceptance tests in this file are gated by VAULT_ACC=1 and mutate a live
// operator-provided Proxmox VE 9.2.10 cluster. Required environment variables
// are PVE_ADDR, PVE_TOKEN_ID, PVE_TOKEN_SECRET, and PVE_TEST_GROUP. The test
// group must be pre-created and safely bound to a test-only role/path before
// running the suite. The authorization canary additionally requires
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
	accRoleName          = "acc"
	accUserPrefix        = "vaultacc"
	accDefaultTTL        = 300
	accDefaultMaxTTL     = 900
	accBehaviorPathEnv   = "PVE_BEHAVIORAL_PATH"
	accBehaviorMarkerEnv = "PVE_BEHAVIORAL_MARKER"
	accDefaultBehavior   = "/version"
	accTestTimeout       = 2 * time.Minute
	accPastExpireBuffer  = 60
	accDefaultWorkers    = 10
	accMaxWorkers        = 10
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

func TestValidateAccBehaviorEnvRequiresMarkerForCustomPath(t *testing.T) {
	err := validateAccBehavioralCanaryEnv(accEnv{BehaviorPath: "/nodes"})
	if err == nil {
		t.Fatal("expected PVE_BEHAVIORAL_PATH without marker to fail")
	}
	if !strings.Contains(err.Error(), accBehaviorMarkerEnv) || !strings.Contains(err.Error(), "TestAccAuthorizationContractCanary") {
		t.Fatalf("validation error = %q; want marker and canary context", err.Error())
	}
}

func TestValidateAccBehaviorEnvRequiresPathForMarker(t *testing.T) {
	err := validateAccBehavioralCanaryEnv(accEnv{BehaviorMarker: "marker"})
	if err == nil {
		t.Fatal("expected PVE_BEHAVIORAL_MARKER without path to fail")
	}
	if !strings.Contains(err.Error(), accBehaviorPathEnv) {
		t.Fatalf("validation error = %q; want behavioral path", err.Error())
	}
}

func TestValidateAccBehaviorEnvRejectsVersionSentinelWithSpecificMessage(t *testing.T) {
	err := validateAccBehavioralCanaryEnv(accEnv{BehaviorPath: accDefaultBehavior})
	if err == nil {
		t.Fatal("expected /version behavioral path sentinel to fail")
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
	resp, err := h.Backend.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/" + accRoleName,
		Storage:   h.Storage,
		Data: map[string]interface{}{
			"group":       h.Env.Group,
			"user_prefix": accUserPrefix,
			"realm":       "pve",
			"ttl":         accDefaultTTL,
			"max_ttl":     accDefaultMaxTTL,
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
	t.Helper()
	secret.Increment = increment
	if secret.IssueTime.IsZero() {
		secret.IssueTime = time.Now()
	}
	req := logical.RenewRequest("creds/"+accRoleName, secret, nil)
	req.Storage = h.Storage
	resp, err := h.Backend.secretTokenRenew(ctx, req, nil)
	if err != nil {
		t.Fatalf("renew secret: %v", err)
	}
	return resp
}

func revokeAccSecret(t *testing.T, ctx context.Context, h accHarness, secret *logical.Secret) {
	t.Helper()
	req := logical.RevokeRequest("creds/"+accRoleName, secret, nil)
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
		t.Fatalf("token request %s %s status=%d; want %d body=%s", method, path, status, want, redactBody(body))
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
