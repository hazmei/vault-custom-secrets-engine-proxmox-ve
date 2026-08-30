package pveapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDeleteTokenEndpointAndIdempotency(t *testing.T) {
	var gotPath string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusInternalServerError)
		if _, writeErr := w.Write([]byte(`{"data":null,"message":"no such token"}`)); writeErr != nil {
			t.Errorf("write response: %v", writeErr)
		}
	}))
	defer server.Close()
	client := makeTestClient(t, server.URL, "admin@pve!old", "secret")
	err := client.DeleteToken(context.Background(), "admin@pve", "old")
	if !errors.Is(err, ErrTokenNotFound) {
		t.Fatalf("DeleteToken error=%v, want ErrTokenNotFound", err)
	}
	if gotPath != "/api2/json/access/users/admin@pve/token/old" {
		t.Fatalf("path=%q", gotPath)
	}
}

func TestTokenNotFoundClassificationIsEndpointSpecific(t *testing.T) {
	body := []byte(`{"data":null,"message":"no such token"}`)
	if got := classifyPVEError(http.StatusInternalServerError, body); got != nil {
		t.Fatalf("global classifier returned token sentinel %v", got)
	}
	if got := classifyTokenPVEError(http.StatusInternalServerError, body, nil); !errors.Is(got, ErrTokenNotFound) {
		t.Fatalf("token classifier=%v, want ErrTokenNotFound", got)
	}
}

func TestTokenExistsConfirmsAbsentToken(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("method=%s, want GET", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		if _, writeErr := w.Write([]byte(`{"data":[]}`)); writeErr != nil {
			t.Errorf("write response: %v", writeErr)
		}
	}))
	defer server.Close()
	client := makeTestClient(t, server.URL, "admin@pve!old", "secret")
	exists, err := client.TokenExists(context.Background(), "admin@pve", "old")
	if err != nil || exists {
		t.Fatalf("TokenExists=(%v, %v), want (false, nil)", exists, err)
	}
}

func TestCreateTokenUsesStandardErrorClassification(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		if _, err := w.Write([]byte(`{"data":null,"message":"no such token"}`)); err != nil {
			t.Errorf("write response: %v", err)
		}
	}))
	defer server.Close()
	client := makeTestClient(t, server.URL, "admin@pve!old", "secret")
	_, err := client.CreateToken(context.Background(), "admin@pve", "new")
	if errors.Is(err, ErrTokenNotFound) {
		t.Fatalf("CreateToken must not use delete-only ErrTokenNotFound classification: %v", err)
	}
}
