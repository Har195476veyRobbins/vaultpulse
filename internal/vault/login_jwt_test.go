package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newJWTMockServer(t *testing.T, statusCode int, token string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		w.WriteHeader(statusCode)
		if statusCode == http.StatusOK {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"auth": map[string]any{
					"client_token":   token,
					"lease_duration": 3600,
					"renewable":      true,
				},
			})
		}
	}))
}

func TestLoginWithJWT_Success(t *testing.T) {
	srv := newJWTMockServer(t, http.StatusOK, "jwt-token-abc")
	defer srv.Close()

	c := &Client{address: srv.URL, http: srv.Client()}
	resp, err := c.LoginWithJWT(context.Background(), JWTLoginRequest{
		Role: "my-role",
		JWT:  "eyJhbGciOiJSUzI1NiJ9.test.sig",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.ClientToken != "jwt-token-abc" {
		t.Errorf("expected token %q, got %q", "jwt-token-abc", resp.ClientToken)
	}
	if resp.LeaseDuration != 3600 {
		t.Errorf("expected lease_duration 3600, got %d", resp.LeaseDuration)
	}
	if !resp.Renewable {
		t.Error("expected renewable to be true")
	}
}

func TestLoginWithJWT_Forbidden(t *testing.T) {
	srv := newJWTMockServer(t, http.StatusForbidden, "")
	defer srv.Close()

	c := &Client{address: srv.URL, http: srv.Client()}
	_, err := c.LoginWithJWT(context.Background(), JWTLoginRequest{
		Role: "my-role",
		JWT:  "bad.jwt.token",
	})
	if err == nil {
		t.Fatal("expected error for forbidden response")
	}
}

func TestLoginWithJWT_EmptyRole(t *testing.T) {
	c := &Client{address: "http://localhost", http: http.DefaultClient}
	_, err := c.LoginWithJWT(context.Background(), JWTLoginRequest{JWT: "some.jwt"})
	if err == nil {
		t.Fatal("expected error for empty role")
	}
}

func TestLoginWithJWT_EmptyJWT(t *testing.T) {
	c := &Client{address: "http://localhost", http: http.DefaultClient}
	_, err := c.LoginWithJWT(context.Background(), JWTLoginRequest{Role: "my-role"})
	if err == nil {
		t.Fatal("expected error for empty jwt")
	}
}

func TestLoginWithJWT_BadURL(t *testing.T) {
	c := &Client{address: "http://127.0.0.1:0", http: http.DefaultClient}
	_, err := c.LoginWithJWT(context.Background(), JWTLoginRequest{
		Role: "my-role",
		JWT:  "some.jwt.token",
	})
	if err == nil {
		t.Fatal("expected error for unreachable server")
	}
}
