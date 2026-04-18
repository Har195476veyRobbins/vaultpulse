package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newUserpassMockServer(t *testing.T, username, token string, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expected := "/v1/auth/userpass/login/" + username
		if r.URL.Path != expected {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
		if status == http.StatusOK {
			resp := map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token":   token,
					"lease_duration": 3600,
					"renewable":      true,
				},
			}
			_ = json.NewEncoder(w).Encode(resp)
		}
	}))
}

func TestLoginWithUserpass_Success(t *testing.T) {
	srv := newUserpassMockServer(t, "alice", "tok-abc", http.StatusOK)
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	tok, err := c.LoginWithUserpass("alice", "secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "tok-abc" {
		t.Errorf("expected tok-abc, got %s", tok)
	}
}

func TestLoginWithUserpass_Forbidden(t *testing.T) {
	srv := newUserpassMockServer(t, "alice", "", http.StatusForbidden)
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_, err := c.LoginWithUserpass("alice", "wrong")
	if err == nil {
		t.Fatal("expected error for forbidden")
	}
}

func TestLoginWithUserpass_EmptyUsername(t *testing.T) {
	c := newTestClient(t, "http://localhost")
	_, err := c.LoginWithUserpass("", "pass")
	if err == nil {
		t.Fatal("expected error for empty username")
	}
}

func TestLoginWithUserpass_EmptyPassword(t *testing.T) {
	c := newTestClient(t, "http://localhost")
	_, err := c.LoginWithUserpass("user", "")
	if err == nil {
		t.Fatal("expected error for empty password")
	}
}

func TestLoginWithUserpass_BadURL(t *testing.T) {
	c := newTestClient(t, "http://127.0.0.1:0")
	_, err := c.LoginWithUserpass("alice", "pass")
	if err == nil {
		t.Fatal("expected error for bad URL")
	}
}
