package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newLDAPMockServer(t *testing.T, username, token string, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/ldap/login/"+username {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
		if status == http.StatusOK {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token":   token,
					"lease_duration": 3600,
				},
			})
		}
	}))
}

func TestLoginWithLDAP_Success(t *testing.T) {
	srv := newLDAPMockServer(t, "alice", "ldap-token-abc", http.StatusOK)
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	token, err := c.LoginWithLDAP("alice", "secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "ldap-token-abc" {
		t.Errorf("expected ldap-token-abc, got %s", token)
	}
}

func TestLoginWithLDAP_Forbidden(t *testing.T) {
	srv := newLDAPMockServer(t, "alice", "", http.StatusForbidden)
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_, err := c.LoginWithLDAP("alice", "wrong")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestLoginWithLDAP_EmptyUsername(t *testing.T) {
	c := newTestClient(t, "http://127.0.0.1")
	_, err := c.LoginWithLDAP("", "pass")
	if err == nil {
		t.Fatal("expected error for empty username")
	}
}

func TestLoginWithLDAP_EmptyPassword(t *testing.T) {
	c := newTestClient(t, "http://127.0.0.1")
	_, err := c.LoginWithLDAP("alice", "")
	if err == nil {
		t.Fatal("expected error for empty password")
	}
}

func TestLoginWithLDAP_BadURL(t *testing.T) {
	c := newTestClient(t, "http://127.0.0.1:0")
	_, err := c.LoginWithLDAP("alice", "pass")
	if err == nil {
		t.Fatal("expected error for bad URL")
	}
}
