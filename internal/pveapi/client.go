// Package pveapi — real HTTP client for the Proxmox VE REST API.
//
// Authentication: Authorization: PVEAPIToken=<user>@<realm>!<tokenid>=<secret>
// Base URL: <address>/api2/json  (address already includes scheme, e.g. https://host:8006)
//
// Error contract: PVE 9.2.10 uses HTTP 500 and 400 with a body for conditions
// that REST would encode as 404/409. Body-string classification is GATED to
// HTTP 400 and 500; all other non-2xx statuses (e.g. 502/503 from a proxy)
// fall through to a generic "HTTP <status>" error to prevent false-positive
// sentinel matches. HTTP 401 and HTTP 403 are genuine statuses to branch on.
// (Confirmed PVE 9.2.10, PVE_PROBES.md Probes 2–6b.)
//
// Secret hygiene: token_secret (the admin credential from config, and the
// issued credential in the token-create response) MUST NOT appear in any error
// string or log line. Token endpoint errors redact the response body.
package pveapi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// httpTimeout is the default timeout for all PVE API calls.
	httpTimeout = 30 * time.Second

	// maxResponseBodyBytes bounds memory used to read a single PVE response.
	// PVE JSON responses are small in practice; 1 MiB leaves ample headroom while
	// preventing unbounded allocation from a compromised endpoint or proxy.
	maxResponseBodyBytes = 1 << 20
)

// Client is the interface every call site uses. All methods that interact
// with PVE entities are declared here; Phase 1 provides full implementations
// for GetVersion and GetPermissions. The remaining methods are fully
// implemented here as well (required by the interface for mock compatibility
// and referenced in Phase 2/3 paths), but are only exercised by unit tests
// with the mock client until those phases are wired.
type Client interface {
	// GetVersion performs GET /version — lightweight reachability check.
	GetVersion(ctx context.Context) (string, error)

	// GetVersionInfo performs GET /version and returns the complete build identity.
	GetVersionInfo(ctx context.Context) (VersionInfo, error)

	// GetPermissions performs GET /access/permissions and returns the
	// effective permission tree for the authenticated token.
	GetPermissions(ctx context.Context) (PermissionTree, error)

	// GetGroup performs GET /access/groups/{group}.
	// Returns ErrGroupNotFound (mapped from HTTP 500 + body "does not exist").
	GetGroup(ctx context.Context, group string) error

	// CreateUser performs POST /access/users.
	// Returns ErrConflict (mapped from HTTP 500 + body "already exists").
	// Returns ErrGroupNotFound (mapped from HTTP 500 + body "no such group") if the
	// group does not exist at issuance time.
	CreateUser(ctx context.Context, req CreateUserRequest) error

	// GetUser performs GET /access/users/{userid} for read-back assertions.
	// Returns ErrUserNotFound (mapped from HTTP 500 + body "no such user").
	GetUser(ctx context.Context, userid string) (UserInfo, error)

	// CreateToken performs POST /access/users/{userid}/token/{tokenid} with
	// privsep=0 (MANDATORY — privsep=1 gives the token an empty ACL and zero
	// effective permissions; see AGENTS.md).
	// privsep=0 is always sent; the parameter is not exposed because there is
	// no legitimate call site that would pass privsep=1.
	// Returns the token secret string on success.
	// Returns ErrConflict (mapped from HTTP 400 + body errors.tokenid "Token already exists").
	// NEVER logs or returns the secret in error messages.
	CreateToken(ctx context.Context, userid, tokenid string) (string, error)

	// UpdateUser performs PUT /access/users/{userid}.
	// PUT is FULL-REPLACE (confirmed PVE 9.2.10, Probe 7): always re-send
	// Groups+Enable+Append=true or group membership is wiped.
	UpdateUser(ctx context.Context, req UpdateUserRequest) error

	// DeleteUser performs DELETE /access/users/{userid}.
	// Returns ErrUserNotFound (mapped from HTTP 500 + body "no such user") — treat
	// as success for idempotent revocation.
	DeleteUser(ctx context.Context, userid string) error
	DeleteToken(ctx context.Context, userid, tokenid string) error
	TokenExists(ctx context.Context, userid, tokenid string) (bool, error)
}

type endpointKind uint8

const (
	endpointStandard endpointKind = iota
	endpointToken
)

// httpClient is the real PVE API client backed by net/http.
type httpClient struct {
	baseURL  string // e.g. "https://pve.example.com:8006/api2/json"
	tokenID  string // full token id: "<user>@<realm>!<tokenid>"
	tokenSec string // token secret — never logged
	http     *http.Client
}

// ClientConfig holds the parameters needed to construct a real httpClient.
type ClientConfig struct {
	Address       string
	TokenID       string
	TokenSecret   string
	TLSSkipVerify bool
	CACert        string
}

// NewClient constructs a real PVE API client from the given config.
// It does NOT perform any network I/O; call GetVersion to test connectivity.
//
// NewClient rejects any address that does not use the https:// scheme.
// Sending the admin token over plain http exposes it in cleartext; the
// tls_skip_verify and ca_cert options are meaningless without TLS.
func NewClient(cfg ClientConfig) (Client, error) {
	parsed, err := url.Parse(cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("pveapi: invalid address %q: %w", cfg.Address, err)
	}
	if parsed.Scheme != "https" {
		return nil, fmt.Errorf("pveapi: address must use https:// scheme; got %q", cfg.Address)
	}

	tlsCfg := &tls.Config{
		InsecureSkipVerify: cfg.TLSSkipVerify, //nolint:gosec // operator-controlled
	}

	if cfg.CACert != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(cfg.CACert)) {
			return nil, fmt.Errorf("pveapi: failed to parse ca_cert PEM")
		}
		tlsCfg.RootCAs = pool
	}

	transport := &http.Transport{TLSClientConfig: tlsCfg}
	hc := &http.Client{
		Timeout:   httpTimeout,
		Transport: transport,
	}

	baseURL := strings.TrimRight(cfg.Address, "/") + "/api2/json"

	return &httpClient{
		baseURL:  baseURL,
		tokenID:  cfg.TokenID,
		tokenSec: cfg.TokenSecret,
		http:     hc,
	}, nil
}

// authHeader returns the PVE API token authorization header value.
// Format: PVEAPIToken=<token_id>=<token_secret>
// where token_id is already in <user>@<realm>!<tokenid> form.
func (c *httpClient) authHeader() string {
	return "PVEAPIToken=" + c.tokenID + "=" + c.tokenSec
}

// doRequest executes an HTTP request against the PVE API.
// The body parameter, if non-nil, is form-encoded.
// redactBody controls whether a non-2xx response body is included in the
// error message (set true for token endpoints to prevent secret leakage).
func (c *httpClient) doRequest(
	ctx context.Context,
	method, path string,
	form url.Values,
	redactBody bool,
	kind endpointKind,
) ([]byte, int, error) {
	var reqBody io.Reader
	if form != nil {
		reqBody = strings.NewReader(form.Encode())
	}

	fullURL := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, method, fullURL, reqBody)
	if err != nil {
		return nil, 0, fmt.Errorf("pveapi: build request %s %s: %w", method, path, err)
	}

	req.Header.Set("Authorization", c.authHeader())
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("pveapi: request %s %s: %w", method, path, err)
	}
	defer resp.Body.Close() //nolint:errcheck // response body close error is not actionable

	body, err := readResponseBody(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("pveapi: read response body %s %s: %w", method, path, err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		classified := classifyPVEError(resp.StatusCode, body)
		if kind == endpointToken {
			classified = classifyTokenPVEError(resp.StatusCode, body, classified)
		}
		if classified != nil {
			return nil, resp.StatusCode, classified
		}
		if redactBody {
			return nil, resp.StatusCode, fmt.Errorf("pveapi: %s %s returned HTTP %d (body redacted)", method, path, resp.StatusCode)
		}
		return nil, resp.StatusCode, fmt.Errorf("pveapi: %s %s returned HTTP %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	return body, resp.StatusCode, nil
}

// readResponseBody reads a PVE response body with a hard byte cap.
func readResponseBody(body io.Reader) ([]byte, error) {
	limited := io.LimitReader(body, maxResponseBodyBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(data) > maxResponseBodyBytes {
		return nil, fmt.Errorf("%w: exceeds %d bytes", ErrResponseTooLarge, maxResponseBodyBytes)
	}
	return data, nil
}

// classifyPVEError inspects the HTTP status code and the decoded body
// to map PVE error conditions to typed sentinel errors.
//
// PVE's error contract (PVE 9.2.10, PVE_PROBES.md Probes 2–6b):
//   - body "already exists"       → ErrConflict      (HTTP 500)
//   - body "Token already exists" → ErrConflict      (HTTP 400, in errors.tokenid NOT message)
//   - body "no such user"         → ErrUserNotFound  (HTTP 500)
//   - body "does not exist"       → ErrGroupNotFound (HTTP 500, e.g. group GET)
//   - body "no such group"        → ErrGroupNotFound (HTTP 500, user create with bad group)
//   - HTTP 401 (any body)         → ErrUnauthenticated
//   - HTTP 403 (any body)         → ErrForbidden
//   - anything else               → nil (caller wraps with status+endpoint)
//
// Body-string matching is GATED to the statuses PVE probes actually confirmed
// (400 and 500).  Any other non-2xx status (502, 503, 404 from a reverse proxy,
// etc.) falls through and returns nil so the caller emits a plain
// "HTTP <status>" error — this prevents a proxy error page containing e.g.
// "the page you requested does not exist" from being misclassified as
// ErrGroupNotFound and silently "succeeding" revocation while PVE users remain live.
//
// The match prefers STRUCTURED fields (message + all errors-map values) to
// avoid false-positive widening from raw-body noise.  The raw body string is
// used as a genuine fallback ONLY when json.Unmarshal fails or both message
// and errors are empty (e.g. a plain-text or malformed response).
//
// DR-2: "no such user" maps to ErrUserNotFound; "does not exist" and
// "no such group" map to ErrGroupNotFound. Call sites use errors.Is to
// distinguish the two without a second body-string scan.
func classifyPVEError(status int, body []byte) error {
	if status == http.StatusUnauthorized {
		return ErrUnauthenticated
	}
	if status == http.StatusForbidden {
		return ErrForbidden
	}

	// Only HTTP 400 and 500 carry PVE's body-string error contract (confirmed
	// PVE 9.2.10, PVE_PROBES.md Probes 2–6b).  Let everything else fall through
	// to the generic "HTTP <status>" error returned by the caller.
	if status != http.StatusInternalServerError && status != http.StatusBadRequest {
		return nil
	}

	if len(body) == 0 {
		return nil
	}

	// Attempt to decode structured fields from the PVE error body.
	var errBody pveErrorBody
	decodeOK := json.Unmarshal(body, &errBody) == nil

	var haystack string
	if decodeOK && (errBody.Message != "" || len(errBody.Errors) > 0) {
		// Prefer structured fields: message + all errors-map values.
		// This ensures we match "Token already exists" even when it's in
		// errors.tokenid rather than message (PVE_PROBES.md Probe 6b).
		var parts []string
		if errBody.Message != "" {
			parts = append(parts, errBody.Message)
		}
		for _, v := range errBody.Errors {
			parts = append(parts, v)
		}
		haystack = strings.ToLower(strings.Join(parts, " "))
	} else {
		// Fallback: scan raw body when JSON decode failed or yielded no fields.
		// Covers plain-text PVE responses and other unexpected shapes.
		haystack = strings.ToLower(string(body))
	}

	switch {
	case strings.Contains(haystack, "token already exists"):
		return ErrConflict
	case strings.Contains(haystack, "already exists"):
		return ErrConflict
	case strings.Contains(haystack, "no such user"):
		// DR-2: user-specific sentinel; revocation treats this as idempotent success.
		return ErrUserNotFound
	case strings.Contains(haystack, "no such group"):
		// DR-2: group-specific sentinel; role-write surfaces as "group does not exist".
		return ErrGroupNotFound
	case strings.Contains(haystack, "does not exist"):
		// DR-2: covers GET /access/groups/{group} → "group 'x' does not exist".
		return ErrGroupNotFound
	}

	return nil
}

func classifyTokenPVEError(status int, body []byte, classified error) error {
	if classified != nil || (status != http.StatusBadRequest && status != http.StatusInternalServerError) {
		return classified
	}
	if strings.Contains(strings.ToLower(string(body)), "no such token") {
		return ErrTokenNotFound
	}
	return nil
}

// GetVersion calls GET /version and returns the PVE version string.
// Used as a lightweight reachability and TLS check on config write.
func (c *httpClient) GetVersion(ctx context.Context) (string, error) {
	info, err := c.GetVersionInfo(ctx)
	if err != nil {
		return "", err
	}
	return info.Version, nil
}

// GetVersionInfo calls GET /version and returns the exact build identity.
// Missing or malformed fields are left for callers that require an exact
// verified-build match to reject.
//
// Neither version method wraps its error with its own name: doRequest already
// reports "pveapi: GET /version returned ...", naming the package and the
// endpoint, and every call site supplies its own context. A method-name wrap
// here would either name the wrong method (GetVersion delegates) or stack two
// of them on one error.
func (c *httpClient) GetVersionInfo(ctx context.Context) (VersionInfo, error) {
	body, _, err := c.doRequest(ctx, http.MethodGet, "/version", nil, false, endpointStandard)
	if err != nil {
		return VersionInfo{}, err
	}

	var resp versionResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return VersionInfo{}, fmt.Errorf("pveapi: parse GET /version response: %w", err)
	}

	return VersionInfo{Version: resp.Data.Version, RepoID: resp.Data.RepoID}, nil
}

// GetPermissions calls GET /access/permissions and returns the effective
// permission tree for the authenticated token.
//
// The returned PermissionTree maps ACL paths to privilege→propagate-flag.
// Use PermissionTree.HasPrivilege to check effective privileges with the
// correct ancestor-path walk.
func (c *httpClient) GetPermissions(ctx context.Context) (PermissionTree, error) {
	body, _, err := c.doRequest(ctx, http.MethodGet, "/access/permissions", nil, false, endpointStandard)
	if err != nil {
		return nil, fmt.Errorf("pveapi: GetPermissions: %w", err)
	}

	var resp permissionsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("pveapi: GetPermissions: parse response: %w", err)
	}

	return resp.Data, nil
}

// GetGroup calls GET /access/groups/{group} to verify the group exists.
// Returns ErrGroupNotFound if PVE responds HTTP 500 + body containing "does not exist".
func (c *httpClient) GetGroup(ctx context.Context, group string) error {
	path := "/access/groups/" + url.PathEscape(group)
	_, _, err := c.doRequest(ctx, http.MethodGet, path, nil, false, endpointStandard)
	if err != nil {
		return fmt.Errorf("pveapi: GetGroup %q: %w", group, err)
	}
	return nil
}

// CreateUser calls POST /access/users to create a synthetic lease user.
//
// When req.Password is set the user is created with a live password in this
// single call; no separate password-setting request is made (the engine's
// API-token authentication cannot use PUT /access/password, which requires a
// password-authenticated ticket — PVE_PROBES.md Probe P0 on
// pve-manager/9.2.14/a1480fa6b8d899cb; 9.2.10 has no password evidence).
//
// Form-encoding notes (from AGENTS.md — both are silent-failure traps):
//   - groups: ONE comma-separated field, never array-repeated.
//   - enable: serialized as literal "1", never bool/omitempty.
//
// Returns ErrConflict if PVE returns HTTP 500 + body "already exists".
// Returns ErrGroupNotFound if PVE returns HTTP 500 + body "no such group".
func (c *httpClient) CreateUser(ctx context.Context, req CreateUserRequest) error {
	form := url.Values{}
	form.Set("userid", req.UserID)
	form.Set("groups", req.Groups) // single CSV field, never array-repeated
	form.Set("expire", fmt.Sprintf("%d", req.Expire))
	if req.Enable {
		form.Set("enable", "1") // explicit literal "1", never bool encoding
	} else {
		form.Set("enable", "0")
	}
	if req.Comment != "" {
		form.Set("comment", req.Comment)
	}
	// Password mode: single-call creation. The credential is live as soon as
	// PVE returns 200 (PVE_PROBES.md Probe P0 on pve-manager/9.2.14/a1480fa6b8d899cb).
	if req.Password != "" {
		form.Set("password", req.Password)
	}

	// redactBody when a password is present: PVE's validation errors name the
	// field rather than echoing the value, but redaction removes the whole
	// class of accidental credential echo from error strings.
	_, _, err := c.doRequest(ctx, http.MethodPost, "/access/users", form, req.Password != "", endpointStandard)
	if err != nil {
		return fmt.Errorf("pveapi: CreateUser %q: %w", req.UserID, err)
	}
	return nil
}

// GetUser calls GET /access/users/{userid} and returns the user's current state.
// Used for read-back assertions after CreateUser and UpdateUser to confirm
// group membership was applied (PVE silently drops unresolvable groups on
// modify/append; on create, PVE rejects with HTTP 500 "no such group" instead).
// Returns ErrUserNotFound if PVE responds HTTP 500 + body "no such user".
func (c *httpClient) GetUser(ctx context.Context, userid string) (UserInfo, error) {
	path := "/access/users/" + url.PathEscape(userid)
	body, _, err := c.doRequest(ctx, http.MethodGet, path, nil, false, endpointStandard)
	if err != nil {
		return UserInfo{}, fmt.Errorf("pveapi: GetUser %q: %w", userid, err)
	}

	var resp userResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return UserInfo{}, fmt.Errorf("pveapi: GetUser %q: parse response: %w", userid, err)
	}

	info := UserInfo{
		Groups:  []string(resp.Data.Groups),
		Enable:  resp.Data.Enable != 0,
		Expire:  resp.Data.Expire,
		Comment: resp.Data.Comment,
	}

	return info, nil
}

// CreateToken calls POST /access/users/{userid}/token/{tokenid} with privsep=0.
//
// MANDATORY: privsep MUST be serialized as the literal "0" (never omitted).
// PVE defaults privsep=1 when the field is absent, giving the token an empty
// ACL with zero effective permissions (confirmed PVE 9.2.10, AGENTS.md).
// privsep=0 is always sent and is not an exposed parameter — there is no
// legitimate call site that would pass privsep=1.
//
// The token secret is returned on success. It is one-time and non-reproducible.
// NEVER log or return it in an error message — token endpoint errors redact body.
//
// Returns ErrConflict if PVE returns HTTP 400 + errors.tokenid "Token already exists".
func (c *httpClient) CreateToken(ctx context.Context, userid, tokenid string) (string, error) {
	path := "/access/users/" + url.PathEscape(userid) + "/token/" + url.PathEscape(tokenid)

	form := url.Values{}
	form.Set("privsep", "0") // explicit literal "0" — NEVER omitted, NEVER "1"

	// redactBody=true: token endpoint responses must never appear in error strings.
	body, _, err := c.doRequest(ctx, http.MethodPost, path, form, true, endpointToken)
	if err != nil {
		// Do not include any body content — could contain the token secret.
		return "", fmt.Errorf("pveapi: CreateToken userid=%q tokenid=%q: %w", userid, tokenid, err)
	}

	var resp tokenCreateResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("pveapi: CreateToken userid=%q tokenid=%q: parse response: %w", userid, tokenid, err)
	}

	if resp.Data.Value == "" {
		return "", fmt.Errorf("pveapi: CreateToken userid=%q tokenid=%q: empty token secret in response", userid, tokenid)
	}

	return resp.Data.Value, nil
}

// UpdateUser calls PUT /access/users/{userid}.
//
// PUT /access/users is FULL-REPLACE (confirmed PVE 9.2.10, PVE_PROBES.md Probe 7).
// Always re-send Groups+Enable+Append=true; omitting Groups wipes membership.
//
// Form-encoding notes:
//   - groups: ONE comma-separated field, never array-repeated.
//   - enable: serialized as "1" (never bool/omitempty).
//   - append: MUST be "1" on renewal PUTs; omitting defaults to replace (append=0).
func (c *httpClient) UpdateUser(ctx context.Context, req UpdateUserRequest) error {
	if err := req.Validate(); err != nil {
		return err
	}

	path := "/access/users/" + url.PathEscape(req.UserID)

	form := url.Values{}
	form.Set("expire", fmt.Sprintf("%d", req.Expire))
	form.Set("groups", req.Groups) // single CSV field, never array-repeated
	if req.Enable {
		form.Set("enable", "1")
	} else {
		form.Set("enable", "0")
	}
	if req.Append {
		form.Set("append", "1") // explicit literal "1" — never omitted on renewal
	}

	_, _, err := c.doRequest(ctx, http.MethodPut, path, form, false, endpointStandard)
	if err != nil {
		return fmt.Errorf("pveapi: UpdateUser %q: %w", req.UserID, err)
	}
	return nil
}

// DeleteUser calls DELETE /access/users/{userid}.
// Cascades to remove the user's tokens, group memberships, and ACL entries.
//
// Returns ErrUserNotFound if PVE responds HTTP 500 + body "no such user" — callers
// should treat ErrUserNotFound as success for idempotent revocation.
func (c *httpClient) DeleteUser(ctx context.Context, userid string) error {
	path := "/access/users/" + url.PathEscape(userid)
	_, _, err := c.doRequest(ctx, http.MethodDelete, path, nil, false, endpointStandard)
	if err != nil {
		return fmt.Errorf("pveapi: DeleteUser %q: %w", userid, err)
	}
	return nil
}

// DeleteToken deletes one API token. Callers must use TokenExists when they
// need positive absence confirmation.
func (c *httpClient) DeleteToken(ctx context.Context, userid, tokenid string) error {
	path := "/access/users/" + url.PathEscape(userid) + "/token/" + url.PathEscape(tokenid)
	_, _, err := c.doRequest(ctx, http.MethodDelete, path, nil, true, endpointToken)
	if err != nil {
		return fmt.Errorf("pveapi: DeleteToken userid=%q tokenid=%q: %w", userid, tokenid, err)
	}
	return nil
}

// TokenExists confirms whether a token remains after deletion by listing the
// user's tokens. A successful empty list is definitive and does not depend on
// the unverified absent-token DELETE contract.
func (c *httpClient) TokenExists(ctx context.Context, userid, tokenid string) (bool, error) {
	path := "/access/users/" + url.PathEscape(userid) + "/token"
	body, _, err := c.doRequest(ctx, http.MethodGet, path, nil, true, endpointToken)
	if err != nil {
		return false, fmt.Errorf("pveapi: TokenExists userid=%q tokenid=%q: %w", userid, tokenid, err)
	}
	var response struct {
		Data []struct {
			TokenID string `json:"tokenid"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return false, fmt.Errorf("pveapi: TokenExists userid=%q tokenid=%q: parse response: %w", userid, tokenid, err)
	}
	for _, token := range response.Data {
		if token.TokenID == tokenid {
			return true, nil
		}
	}
	return false, nil
}

// ensure httpClient implements Client at compile time.
var _ Client = (*httpClient)(nil)
