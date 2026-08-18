// Package pveapi — in-memory mock client for unit tests.
//
// MockClient implements Client with programmable behavior:
//   - Pre-seed state (groups, users) for GetGroup/GetUser responses.
//   - Inject errors for specific calls via per-method error fields.
//   - Track calls for assertions (CallLog).
//
// Usage:
//
//	mc := &MockClient{}
//	mc.GetVersionFn = func(ctx context.Context) (string, error) {
//	    return "9.2.10", nil
//	}
//	// or use the defaults (nil Fn fields fall back to simple happy-path behavior)
package pveapi

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

// Call records a single method invocation on the mock.
type Call struct {
	Method string
	Args   []interface{}
}

// MockClient is a thread-safe in-memory PVE API client for unit tests.
// All Fn fields default to nil; when nil, the mock uses built-in defaults
// (happy-path behavior, backed by in-memory state maps).
type MockClient struct {
	mu sync.Mutex

	// CallLog records every method call for assertion in tests.
	CallLog []Call

	// In-memory state (used by default implementations).
	// Groups is a set of known group names; GetGroup returns ErrGroupNotFound for unknown groups.
	Groups map[string]bool
	// Users maps userid → UserInfo; pre-seed for GetUser; CreateUser adds entries.
	Users map[string]UserInfo

	// Per-method override functions. When non-nil, the Fn is called instead of
	// the default behavior. This allows injecting errors on specific calls.
	GetVersionFn     func(ctx context.Context) (string, error)
	GetPermissionsFn func(ctx context.Context) (PermissionTree, error)
	GetGroupFn       func(ctx context.Context, group string) error
	CreateUserFn     func(ctx context.Context, req CreateUserRequest) error
	GetUserFn        func(ctx context.Context, userid string) (UserInfo, error)
	CreateTokenFn    func(ctx context.Context, userid, tokenid string) (string, error)
	UpdateUserFn     func(ctx context.Context, req UpdateUserRequest) error
	DeleteUserFn     func(ctx context.Context, userid string) error

	// CreateUserError, if non-nil, is returned by the default CreateUser
	// implementation (the Fn override takes precedence if set).
	CreateUserError error

	// GetUserError, if non-nil, is returned by the default GetUser impl.
	GetUserError error

	// CreateTokenError, if non-nil, is returned by the default CreateToken impl.
	CreateTokenError error

	// DeleteUserError, if non-nil, is returned by the default DeleteUser impl.
	DeleteUserError error

	// GetPermissionsResult, if non-nil, is returned by the default GetPermissions impl.
	GetPermissionsResult PermissionTree

	// CreateTokenResult is the token secret returned by the default CreateToken impl.
	// Defaults to "mock-token-secret".
	CreateTokenResult string
}

func (m *MockClient) log(method string, args ...interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.CallLog = append(m.CallLog, Call{Method: method, Args: args})
}

// HasCall returns true if the given method was called at least once.
func (m *MockClient) HasCall(method string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.CallLog {
		if c.Method == method {
			return true
		}
	}
	return false
}

// CallsFor returns all recorded calls for the given method.
func (m *MockClient) CallsFor(method string) []Call {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result []Call
	for _, c := range m.CallLog {
		if c.Method == method {
			result = append(result, c)
		}
	}
	return result
}

// DeleteUserCalls returns the userids passed to DeleteUser calls.
func (m *MockClient) DeleteUserCalls() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result []string
	for _, c := range m.CallLog {
		if c.Method == "DeleteUser" && len(c.Args) > 0 {
			if uid, ok := c.Args[0].(string); ok {
				result = append(result, uid)
			}
		}
	}
	return result
}

// GetVersion implements Client.
func (m *MockClient) GetVersion(ctx context.Context) (string, error) {
	m.log("GetVersion")
	if m.GetVersionFn != nil {
		return m.GetVersionFn(ctx)
	}
	return "9.2.10", nil
}

// GetPermissions implements Client.
func (m *MockClient) GetPermissions(ctx context.Context) (PermissionTree, error) {
	m.log("GetPermissions")
	if m.GetPermissionsFn != nil {
		return m.GetPermissionsFn(ctx)
	}
	if m.GetPermissionsResult != nil {
		return m.GetPermissionsResult, nil
	}
	// Default: return a tree with full privileges at /access/groups with propagate=1.
	return PermissionTree{
		"/access/groups": {
			"User.Modify": 1,
			"Sys.Audit":   1,
		},
	}, nil
}

// GetGroup implements Client.
func (m *MockClient) GetGroup(ctx context.Context, group string) error {
	m.log("GetGroup", group)
	if m.GetGroupFn != nil {
		return m.GetGroupFn(ctx, group)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Groups != nil {
		if !m.Groups[group] {
			return fmt.Errorf("pveapi: GetGroup %q: %w", group, ErrGroupNotFound)
		}
		return nil
	}
	// Default: group exists.
	return nil
}

// CreateUser implements Client.
func (m *MockClient) CreateUser(ctx context.Context, req CreateUserRequest) error {
	m.log("CreateUser", req)
	if m.CreateUserFn != nil {
		return m.CreateUserFn(ctx, req)
	}
	if m.CreateUserError != nil {
		return m.CreateUserError
	}
	// Default: create user in memory.
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Users == nil {
		m.Users = make(map[string]UserInfo)
	}
	// Parse groups from CSV.
	var groups []string
	if req.Groups != "" {
		for _, g := range strings.Split(req.Groups, ",") {
			g = strings.TrimSpace(g)
			if g != "" {
				// Reject unresolvable groups: real PVE returns HTTP 500 "no such group"
				// on POST /access/users when a requested group does not exist.
				// PVE silently drops unknown groups on modify/append, but REJECTS on create.
				if m.Groups != nil && !m.Groups[g] {
					return fmt.Errorf("pveapi: CreateUser %q: group %q: %w", req.UserID, g, ErrGroupNotFound)
				}
				groups = append(groups, g)
			}
		}
	}
	m.Users[req.UserID] = UserInfo{
		Groups:  groups,
		Enable:  req.Enable,
		Expire:  req.Expire,
		Comment: req.Comment,
	}
	return nil
}

// GetUser implements Client.
func (m *MockClient) GetUser(ctx context.Context, userid string) (UserInfo, error) {
	m.log("GetUser", userid)
	if m.GetUserFn != nil {
		return m.GetUserFn(ctx, userid)
	}
	if m.GetUserError != nil {
		return UserInfo{}, m.GetUserError
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Users != nil {
		if info, ok := m.Users[userid]; ok {
			return info, nil
		}
	}
	return UserInfo{}, fmt.Errorf("pveapi: GetUser %q: %w", userid, ErrUserNotFound)
}

// CreateToken implements Client.
func (m *MockClient) CreateToken(ctx context.Context, userid, tokenid string) (string, error) {
	m.log("CreateToken", userid, tokenid)
	if m.CreateTokenFn != nil {
		return m.CreateTokenFn(ctx, userid, tokenid)
	}
	if m.CreateTokenError != nil {
		return "", m.CreateTokenError
	}
	secret := m.CreateTokenResult
	if secret == "" {
		secret = "mock-token-secret"
	}
	return secret, nil
}

// UpdateUser implements Client.
func (m *MockClient) UpdateUser(ctx context.Context, req UpdateUserRequest) error {
	m.log("UpdateUser", req)
	if m.UpdateUserFn != nil {
		return m.UpdateUserFn(ctx, req)
	}
	// Default: update user in memory.
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Users == nil {
		return fmt.Errorf("pveapi: UpdateUser %q: %w", req.UserID, ErrUserNotFound)
	}
	info, ok := m.Users[req.UserID]
	if !ok {
		return fmt.Errorf("pveapi: UpdateUser %q: %w", req.UserID, ErrUserNotFound)
	}
	info.Expire = req.Expire
	info.Enable = req.Enable
	// Re-parse groups from CSV (full-replace semantics).
	info.Groups = nil
	if req.Groups != "" {
		for _, g := range strings.Split(req.Groups, ",") {
			g = strings.TrimSpace(g)
			if g != "" {
				info.Groups = append(info.Groups, g)
			}
		}
	}
	m.Users[req.UserID] = info
	return nil
}

// DeleteUser implements Client.
func (m *MockClient) DeleteUser(ctx context.Context, userid string) error {
	m.log("DeleteUser", userid)
	if m.DeleteUserFn != nil {
		return m.DeleteUserFn(ctx, userid)
	}
	if m.DeleteUserError != nil {
		return m.DeleteUserError
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Users != nil {
		if _, ok := m.Users[userid]; !ok {
			// Real PVE: DELETE /access/users/{userid} returns HTTP 500 "no such user"
			// when the user is absent (not 404). Confirmed PVE 9.2.10, PVE_PROBES.md Probe 3.
			return fmt.Errorf("pveapi: DeleteUser %q: %w", userid, ErrUserNotFound)
		}
		delete(m.Users, userid)
	}
	return nil
}

// ensure MockClient implements Client at compile time.
var _ Client = (*MockClient)(nil)
