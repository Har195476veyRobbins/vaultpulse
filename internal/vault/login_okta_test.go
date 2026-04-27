package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newOktaMockServer(t *testing.T, username string, statusCode int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/okta/login/"+username {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(statusCode)
		if statusCode == http.StatusOK {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token":   "okta-token-abc",
					"lease_duration": 3600,
					"renewable":      true,
				},
			})
		}
	}))
}

func TestLoginWithOkta_Success(t *testing.T) {
	srv := newOktaMockServer(t, "alice", http.StatusOK)
	defer srv.Close()

	client := newTestClient(t, srv.URL)
	resp, err := client.LoginWithOkta("alice", "s3cr3t")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Auth.ClientToken != "okta-token-abc" {
		t.Errorf("expected token %q, got %q", "okta-token-abc", resp.Auth.ClientToken)
	}
	if !resp.Auth.Renewable {
		t.Error("expected token to be renewable")
	}
}

func TestLoginWithOkta_Forbidden(t *testing.T) {
	srv := newOktaMockServer(t, "alice", http.StatusForbidden)
	defer srv.Close()

	client := newTestClient(t, srv.URL)
	_, err := client.LoginWithOkta("alice", "wrongpass")
	if err == nil {
		t.Fatal("expected error for forbidden, got nil")
	}
}

func TestLoginWithOkta_EmptyUsername(t *testing.T) {
	client := newTestClient(t, "http://127.0.0.1")
	_, err := client.LoginWithOkta("", "password")
	if err == nil {
		t.Fatal("expected error for empty username")
	}
}

func TestLoginWithOkta_EmptyPassword(t *testing.T) {
	client := newTestClient(t, "http://127.0.0.1")
	_, err := client.LoginWithOkta("alice", "")
	if err == nil {
		t.Fatal("expected error for empty password")
	}
}

func TestLoginWithOkta_BadURL(t *testing.T) {
	client := newTestClient(t, "http://127.0.0.1:0")
	_, err := client.LoginWithOkta("alice", "pass")
	if err == nil {
		t.Fatal("expected error for bad URL")
	}
}
