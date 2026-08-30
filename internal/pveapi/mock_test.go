package pveapi

import (
	"context"
	"testing"
)

func TestMockTokenExistsDefaultIsTrue(t *testing.T) {
	mock := &MockClient{}
	exists, err := mock.TokenExists(context.Background(), "user@pve", "token")
	if err != nil || !exists {
		t.Fatalf("TokenExists=(%v, %v), want (true, nil)", exists, err)
	}
}

func TestMockTokenExistsExplicitTrue(t *testing.T) {
	value := true
	mock := &MockClient{TokenExistsResult: &value}
	exists, err := mock.TokenExists(context.Background(), "user@pve", "token")
	if err != nil || !exists {
		t.Fatalf("TokenExists=(%v, %v), want (true, nil)", exists, err)
	}
}

func TestMockTokenExistsExplicitFalse(t *testing.T) {
	value := false
	mock := &MockClient{TokenExistsResult: &value}
	exists, err := mock.TokenExists(context.Background(), "user@pve", "token")
	if err != nil || exists {
		t.Fatalf("TokenExists=(%v, %v), want (false, nil)", exists, err)
	}
}
