package vault_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yourusername/vaultpulse/internal/vault"
)

func newOIDCMockServer(t *testing.T, statusCode int, body interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		_ = json.NewEncoder(w).Encode(body)
	}))
}

func TestLoginWithOIDC_Success(t *testing.T) {
	payload := map[string]interface{}{
		"auth": map[string]interface{}{
			"client_token":   "s.oidctoken",
			"lease_duration": 3600,
			"renewable":      true,
		},
	}
	srv := newOIDCMockServer(t, http.StatusOK, payload)
	defer srv.Close()

	client, err := vault.NewClient(vault.Config{Address: srv.URL, Token: "root"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	res, err := client.LoginWithOIDC(context.Background(), vault.OIDCLoginRequest{
		Role:  "my-role",
		Token: "eyJhbGciOiJSUzI1NiJ9.test",
	})
	if err != nil {
		t.Fatalf("LoginWithOIDC: %v", err)
	}
	if res.ClientToken != "s.oidctoken" {
		t.Errorf("expected client_token s.oidctoken, got %q", res.ClientToken)
	}
	if res.LeaseDuration != 3600 {
		t.Errorf("expected lease_duration 3600, got %d", res.LeaseDuration)
	}
	if !res.Renewable {
		t.Error("expected renewable true")
	}
}

func TestLoginWithOIDC_Forbidden(t *testing.T) {
	srv := newOIDCMockServer(t, http.StatusForbidden, map[string]string{"errors": "permission denied"})
	defer srv.Close()

	client, _ := vault.NewClient(vault.Config{Address: srv.URL, Token: "root"})
	_, err := client.LoginWithOIDC(context.Background(), vault.OIDCLoginRequest{
		Role:  "my-role",
		Token: "bad-token",
	})
	if err == nil {
		t.Fatal("expected error for 403, got nil")
	}
}

func TestLoginWithOIDC_EmptyRole(t *testing.T) {
	client, _ := vault.NewClient(vault.Config{Address: "http://127.0.0.1", Token: "root"})
	_, err := client.LoginWithOIDC(context.Background(), vault.OIDCLoginRequest{
		Token: "eyJhbGciOiJSUzI1NiJ9.test",
	})
	if err == nil {
		t.Fatal("expected error for empty role")
	}
}

func TestLoginWithOIDC_EmptyToken(t *testing.T) {
	client, _ := vault.NewClient(vault.Config{Address: "http://127.0.0.1", Token: "root"})
	_, err := client.LoginWithOIDC(context.Background(), vault.OIDCLoginRequest{
		Role: "my-role",
	})
	if err == nil {
		t.Fatal("expected error for empty token")
	}
}

func TestLoginWithOIDC_BadURL(t *testing.T) {
	client, _ := vault.NewClient(vault.Config{Address: "http://127.0.0.1:0", Token: "root"})
	_, err := client.LoginWithOIDC(context.Background(), vault.OIDCLoginRequest{
		Role:  "my-role",
		Token: "eyJhbGciOiJSUzI1NiJ9.test",
	})
	if err == nil {
		t.Fatal("expected error for unreachable server")
	}
}
