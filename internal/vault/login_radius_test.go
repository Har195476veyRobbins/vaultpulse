package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newRADIUSMockServer(t *testing.T, status int, token string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"auth": map[string]interface{}{
				"client_token":   token,
				"lease_duration": 3600,
				"renewable":      true,
			},
		})
	}))
}

func TestLoginWithRADIUS_Success(t *testing.T) {
	srv := newRADIUSMockServer(t, http.StatusOK, "radius-token-abc")
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	res, err := c.LoginWithRADIUS("alice", "s3cr3t", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.ClientToken != "radius-token-abc" {
		t.Errorf("expected token %q, got %q", "radius-token-abc", res.ClientToken)
	}
	if res.LeaseDuration != 3600 {
		t.Errorf("expected lease duration 3600, got %d", res.LeaseDuration)
	}
	if !res.Renewable {
		t.Error("expected renewable to be true")
	}
}

func TestLoginWithRADIUS_Forbidden(t *testing.T) {
	srv := newRADIUSMockServer(t, http.StatusForbidden, "")
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_, err := c.LoginWithRADIUS("alice", "wrongpass", "radius")
	if err == nil {
		t.Fatal("expected error for forbidden status")
	}
}

func TestLoginWithRADIUS_EmptyUsername(t *testing.T) {
	c := newTestClient(t, "http://127.0.0.1")
	_, err := c.LoginWithRADIUS("", "pass", "")
	if err == nil {
		t.Fatal("expected error for empty username")
	}
}

func TestLoginWithRADIUS_EmptyPassword(t *testing.T) {
	c := newTestClient(t, "http://127.0.0.1")
	_, err := c.LoginWithRADIUS("alice", "", "")
	if err == nil {
		t.Fatal("expected error for empty password")
	}
}

func TestLoginWithRADIUS_BadURL(t *testing.T) {
	c := newTestClient(t, "http://127.0.0.1:0")
	_, err := c.LoginWithRADIUS("alice", "pass", "")
	if err == nil {
		t.Fatal("expected error for unreachable server")
	}
}
