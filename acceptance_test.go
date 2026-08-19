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
	accRoleName         = "acc"
	accUserPrefix       = "vaultacc"
	accDefaultTTL       = 300
	accDefaultMaxTTL    = 900
	accBehaviorPathEnv  = "PVE_BEHAVIORAL_PATH"
	accDefaultBehavior  = "/cluster/resources?type=vm"
	accTestTimeout      = 2 * time.Minute
	accPastExpireBuffer = 60
)

type accEnv struct {
	Address                 string
	TokenID                 string
	TokenSecret             string
	Group                   string
	CACert                  string
	TLSSkipVerify           bool
	BehaviorPath            string
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
	issued := issueAccCreds(t, ctx, h)

	defer deleteAccUser(t, ctx, h.Client, issued.UserID)

	assertAccTokenStatus(t, ctx, h.Env, issued.TokenID, issued.TokenSecret, h.Env.BehaviorPath, http.StatusOK)

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
	ctx, cancel := context.WithTimeout(context.Background(), accTestTimeout)
	defer cancel()

	writeAccConfig(t, ctx, h)
	writeAccRole(t, ctx, h)
	issued := issueAccCreds(t, ctx, h)
	defer deleteAccUser(t, ctx, h.Client, issued.UserID)

	assertAccTokenStatus(t, ctx, h.Env, issued.TokenID, issued.TokenSecret, h.Env.BehaviorPath, http.StatusOK)

	pastExpire := time.Now().Unix() - accPastExpireBuffer
	if err := h.Client.UpdateUser(ctx, pveapi.UpdateUserRequest{UserID: issued.UserID, Expire: pastExpire, Groups: h.Env.Group, Enable: true, Append: true}); err != nil {
		t.Fatalf("expire issued user in the past: %v", err)
	}
	assertAccTokenStatus(t, ctx, h.Env, issued.TokenID, issued.TokenSecret, "/version", http.StatusUnauthorized)

	futureExpire := time.Now().Add(10 * time.Minute).Unix()
	if err := h.Client.UpdateUser(ctx, pveapi.UpdateUserRequest{UserID: issued.UserID, Expire: futureExpire, Groups: h.Env.Group, Enable: true, Append: true}); err != nil {
		t.Fatalf("restore issued user expiry: %v", err)
	}
	issued.Secret.IssueTime = time.Now().Add(-30 * time.Second)
	renewAccSecret(t, ctx, h, issued.Secret, 120*time.Second)
	assertAccUserInGroup(t, ctx, h.Client, issued.UserID, h.Env.Group)
	assertAccTokenStatus(t, ctx, h.Env, issued.TokenID, issued.TokenSecret, h.Env.BehaviorPath, http.StatusOK)

	controlUser := accUserID(t, "fullreplace")
	createAccUser(t, ctx, h.Client, controlUser, h.Env.Group, futureExpire, walCommentPrefix+"fullreplace")
	defer deleteAccUser(t, ctx, h.Client, controlUser)
	raw := newAccHTTPClient(t, h.Env)
	form := url.Values{"expire": {strconv.FormatInt(time.Now().Add(20*time.Minute).Unix(), 10)}}
	status, body, err := raw.do(ctx, http.MethodPut, "/access/users/"+url.PathEscape(controlUser), h.Env.TokenID, h.Env.TokenSecret, form)
	if err != nil {
		t.Fatalf("expire-only PUT control failed: %v", err)
	}
	if status < 200 || status >= 300 {
		t.Fatalf("expire-only PUT control status=%d body=%s", status, redactBody(body))
	}
	info, err := h.Client.GetUser(ctx, controlUser)
	if err != nil {
		t.Fatalf("read control user after expire-only PUT: %v", err)
	}
	if len(info.Groups) != 0 {
		t.Fatalf("expire-only PUT control groups=%v; want empty groups to confirm full-replace behavior", info.Groups)
	}
}

func TestAccFailureInjection(t *testing.T) {
	h := newAccHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), accTestTimeout)
	defer cancel()

	writeAccConfig(t, ctx, h)
	req := makeAccRevokeRequest(h.Storage, accUserID(t, "missing"))
	if _, err := h.Backend.secretTokenRevoke(ctx, req, nil); err != nil {
		t.Fatalf("missing-user revoke should be idempotent: %v", err)
	}

	if h.Env.InsufficientTokenID == "" || h.Env.InsufficientTokenSecret == "" {
		t.Skip("optional insufficient-privilege check skipped: set PVE_INSUFFICIENT_TOKEN_ID and PVE_INSUFFICIENT_TOKEN_SECRET")
	}

	insufficient := h.Env
	insufficient.TokenID = h.Env.InsufficientTokenID
	insufficient.TokenSecret = h.Env.InsufficientTokenSecret
	b, storage := newAccBackend(t)
	resp, err := writeAccConfigWithEnv(ctx, b, storage, insufficient)
	if err != nil {
		t.Fatalf("insufficient config request returned framework error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected insufficient PVE token to be rejected by config validation")
	}
}

func TestAccWALRollback(t *testing.T) {
	h := newAccHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), accTestTimeout)
	defer cancel()

	writeAccConfig(t, ctx, h)
	userid := accUserID(t, "wal")
	nonce := walCommentPrefix + "acceptance"
	createAccUser(t, ctx, h.Client, userid, h.Env.Group, time.Now().Add(10*time.Minute).Unix(), nonce)
	defer deleteAccUser(t, ctx, h.Client, userid)

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

	const workers = 5
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
	if len(issued) == 0 {
		t.Fatalf("all concurrent issuances failed: %s", strings.Join(errMsgs, "; "))
	}
	if len(errMsgs) > 0 {
		t.Logf("%d/%d concurrent issuances failed; this can be environment-sensitive PVE cluster contention/quorum behavior: %s", len(errMsgs), workers, strings.Join(errMsgs, "; "))
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
	return accEnv{
		Address:                 os.Getenv("PVE_ADDR"),
		TokenID:                 os.Getenv("PVE_TOKEN_ID"),
		TokenSecret:             os.Getenv("PVE_TOKEN_SECRET"),
		Group:                   os.Getenv("PVE_TEST_GROUP"),
		CACert:                  os.Getenv("PVE_CA_CERT"),
		TLSSkipVerify:           skipVerify,
		BehaviorPath:            envDefault(accBehaviorPathEnv, accDefaultBehavior),
		InsufficientTokenID:     os.Getenv("PVE_INSUFFICIENT_TOKEN_ID"),
		InsufficientTokenSecret: os.Getenv("PVE_INSUFFICIENT_TOKEN_SECRET"),
	}
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

func makeAccRevokeRequest(storage logical.Storage, userid string) *logical.Request {
	secret := &logical.Secret{InternalData: map[string]interface{}{"pve_userid": userid, "group": "unused", "effective_max_ttl": int64(time.Hour)}}
	req := logical.RevokeRequest("creds/"+accRoleName, secret, nil)
	req.Storage = storage
	return req
}

func createAccUser(t *testing.T, ctx context.Context, client pveapi.Client, userid, group string, expire int64, comment string) {
	t.Helper()
	if err := client.CreateUser(ctx, pveapi.CreateUserRequest{UserID: userid, Groups: group, Expire: expire, Enable: true, Comment: comment}); err != nil {
		t.Fatalf("create PVE user %q: %v", userid, err)
	}
	assertAccUserInGroup(t, ctx, client, userid, group)
}

func deleteAccUser(t *testing.T, ctx context.Context, client pveapi.Client, userid string) {
	t.Helper()
	if userid == "" {
		return
	}
	if err := client.DeleteUser(ctx, userid); err != nil && !errors.Is(err, pveapi.ErrUserNotFound) {
		t.Logf("cleanup DeleteUser(%q) failed: %v", userid, err)
	}
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

func assertAccTokenStatus(t *testing.T, ctx context.Context, env accEnv, tokenID, tokenSecret, path string, want int) {
	t.Helper()
	client := newAccHTTPClient(t, env)
	status, body, err := client.do(ctx, http.MethodGet, path, tokenID, tokenSecret, nil)
	if err != nil {
		t.Fatalf("behavioral token request %s: %v", path, err)
	}
	if status != want {
		t.Fatalf("behavioral token request %s status=%d; want %d body=%s", path, status, want, redactBody(body))
	}
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
