// Package pveapi — real HTTP client for the Proxmox VE REST API.
//
// Authentication: Authorization: PVEAPIToken=<user>@<realm>!<tokenid>=<secret>
// Base URL: <address>/api2/json  (address already includes scheme, e.g. https://host:8006)
//
// Error contract: PVE 9.2.10 uses HTTP 500 and 400 with a body for conditions
// that REST would encode as 404/409. Error classification is GATED to HTTP 400
// and 500; all other non-2xx statuses (e.g. 502/503 from a proxy) fall through
// to a generic "HTTP <status>" error to prevent false-positive sentinel matches.
// Only HTTP 403 is a genuine status to branch on.
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

	// GetPermissions performs GET /access/permissions and returns the
	// effective permission tree for the authenticated token.
	GetPermissions(ctx context.Context) (PermissionTree, error)

	// GetGroup performs GET /access/groups/{group}.
	// Returns ErrNotFound (mapped from HTTP 500 + body "does not exist").
	GetGroup(ctx context.Context, group string) error

	// CreateUser performs POST /access/users.
	// Returns ErrConflict (mapped from HTTP 500 + body "already exists").
	// Returns ErrNotFound (mapped from HTTP 500 + body "no such group") if the
	// group does not exist at issuance time.
	CreateUser(ctx context.Context, req CreateUserRequest) error

	// GetUser performs GET /access/users/{userid} for read-back assertions.
	// Returns ErrNotFound (mapped from HTTP 500 + body "no such user").
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
	// Returns ErrNotFound (mapped from HTTP 500 + body "no such user") — treat
	// as success for idempotent revocation.
	DeleteUser(ctx context.Context, userid string) error
}

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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("pveapi: read response body %s %s: %w", method, path, err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		classified := classifyPVEError(resp.StatusCode, body)
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

// classifyPVEError inspects the HTTP status code and the decoded body
// to map PVE error conditions to typed sentinel errors.
//
// PVE's error contract (PVE 9.2.10, PVE_PROBES.md Probes 2–6b):
//   - body "already exists"       → ErrConflict  (HTTP 500)
//   - body "Token already exists" → ErrConflict  (HTTP 400, in errors.tokenid NOT message)
//   - body "no such user"         → ErrNotFound  (HTTP 500)
//   - body "does not exist"       → ErrNotFound  (HTTP 500, e.g. group GET)
//   - body "no such group"        → ErrNotFound  (HTTP 500, user create with bad group)
//   - HTTP 403 (any body)         → ErrForbidden
//   - anything else               → nil (caller wraps with status+endpoint)
//
// Body-string matching is GATED to the statuses PVE probes actually confirmed
// (400 and 500).  Any other non-2xx status (502, 503, 404 from a reverse proxy,
// etc.) falls through and returns nil so the caller emits a plain
// "HTTP <status>" error — this prevents a proxy error page containing e.g.
// "the page you requested does not exist" from being misclassified as
// ErrNotFound and silently "succeeding" revocation while PVE users remain live.
//
// The match prefers STRUCTURED fields (message + all errors-map values) to
// avoid false-positive widening from raw-body noise.  The raw body string is
// used as a genuine fallback ONLY when json.Unmarshal fails or both message
// and errors are empty (e.g. a plain-text or malformed response).
func classifyPVEError(status int, body []byte) error {
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
		return ErrNotFound
	case strings.Contains(haystack, "no such group"):
		return ErrNotFound
	case strings.Contains(haystack, "does not exist"):
		return ErrNotFound
	}

	return nil
}

// GetVersion calls GET /version and returns the PVE version string.
// Used as a lightweight reachability and TLS check on config write.
func (c *httpClient) GetVersion(ctx context.Context) (string, error) {
	body, _, err := c.doRequest(ctx, http.MethodGet, "/version", nil, false)
	if err != nil {
		return "", fmt.Errorf("pveapi: GetVersion: %w", err)
	}

	var resp versionResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("pveapi: GetVersion: parse response: %w", err)
	}

	return resp.Data.Version, nil
}

// GetPermissions calls GET /access/permissions and returns the effective
// permission tree for the authenticated token.
//
// The returned PermissionTree maps ACL paths to privilege→propagate-flag.
// Use PermissionTree.HasPrivilege to check effective privileges with the
// correct ancestor-path walk.
func (c *httpClient) GetPermissions(ctx context.Context) (PermissionTree, error) {
	body, _, err := c.doRequest(ctx, http.MethodGet, "/access/permissions", nil, false)
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
// Returns ErrNotFound if PVE responds HTTP 500 + body containing "does not exist".
func (c *httpClient) GetGroup(ctx context.Context, group string) error {
	path := "/access/groups/" + url.PathEscape(group)
	_, _, err := c.doRequest(ctx, http.MethodGet, path, nil, false)
	if err != nil {
		return fmt.Errorf("pveapi: GetGroup %q: %w", group, err)
	}
	return nil
}

// CreateUser calls POST /access/users to create a synthetic lease user.
//
// Form-encoding notes (from AGENTS.md — both are silent-failure traps):
//   - groups: ONE comma-separated field, never array-repeated.
//   - enable: serialized as literal "1", never bool/omitempty.
//
// Returns ErrConflict if PVE returns HTTP 500 + body "already exists".
// Returns ErrNotFound if PVE returns HTTP 500 + body "no such group".
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

	_, _, err := c.doRequest(ctx, http.MethodPost, "/access/users", form, false)
	if err != nil {
		return fmt.Errorf("pveapi: CreateUser %q: %w", req.UserID, err)
	}
	return nil
}

// GetUser calls GET /access/users/{userid} and returns the user's current state.
// Used for read-back assertions after CreateUser and UpdateUser to confirm
// group membership was applied (PVE silently drops unresolvable groups on
// modify/append; on create, PVE rejects with HTTP 500 "no such group" instead).
// Returns ErrNotFound if PVE responds HTTP 500 + body "no such user".
func (c *httpClient) GetUser(ctx context.Context, userid string) (UserInfo, error) {
	path := "/access/users/" + url.PathEscape(userid)
	body, _, err := c.doRequest(ctx, http.MethodGet, path, nil, false)
	if err != nil {
		return UserInfo{}, fmt.Errorf("pveapi: GetUser %q: %w", userid, err)
	}

	var resp userResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return UserInfo{}, fmt.Errorf("pveapi: GetUser %q: parse response: %w", userid, err)
	}

	info := UserInfo{
		Enable: resp.Data.Enable != 0,
		Expire: resp.Data.Expire,
	}
	if resp.Data.Groups != "" {
		// PVE returns groups as a comma-separated string.
		for _, g := range strings.Split(resp.Data.Groups, ",") {
			g = strings.TrimSpace(g)
			if g != "" {
				info.Groups = append(info.Groups, g)
			}
		}
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
	body, _, err := c.doRequest(ctx, http.MethodPost, path, form, true)
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

	_, _, err := c.doRequest(ctx, http.MethodPut, path, form, false)
	if err != nil {
		return fmt.Errorf("pveapi: UpdateUser %q: %w", req.UserID, err)
	}
	return nil
}

// DeleteUser calls DELETE /access/users/{userid}.
// Cascades to remove the user's tokens, group memberships, and ACL entries.
//
// Returns ErrNotFound if PVE responds HTTP 500 + body "no such user" — callers
// should treat ErrNotFound as success for idempotent revocation.
func (c *httpClient) DeleteUser(ctx context.Context, userid string) error {
	path := "/access/users/" + url.PathEscape(userid)
	_, _, err := c.doRequest(ctx, http.MethodDelete, path, nil, false)
	if err != nil {
		return fmt.Errorf("pveapi: DeleteUser %q: %w", userid, err)
	}
	return nil
}

// ensure httpClient implements Client at compile time.
var _ Client = (*httpClient)(nil)
