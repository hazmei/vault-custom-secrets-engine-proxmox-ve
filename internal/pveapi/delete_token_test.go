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
