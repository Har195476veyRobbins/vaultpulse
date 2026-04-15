package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newAppRoleMockServer(t *testing.T, statusCode int, token string, leaseDuration int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/approle/login" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(statusCode)
		if statusCode == http.StatusOK {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token":   token,
					"lease_duration": leaseDuration,
					"renewable":      true,
				},
			})
		}
	}))
}

func TestLoginWithAppRole_Success(t *testing.T) {
	srv := newAppRoleMockServer(t, http.StatusOK, "s.testtoken", 3600)
	defer srv.Close()

	c, err := NewClient(srv.URL, "ignored")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	result, err := c.LoginWithAppRole(AppRoleCredentials{RoleID: "my-role", SecretID: "my-secret"})
	if err != nil {
		t.Fatalf("LoginWithAppRole: %v", err)
	}

	if result.Token != "s.testtoken" {
		t.Errorf("expected token s.testtoken, got %s", result.Token)
	}
	if !result.Renewable {
		t.Error("expected renewable to be true")
	}
	if result.ExpiresAt.Before(time.Now().Add(3500 * time.Second)) {
		t.Error("expected ExpiresAt to be ~1 hour from now")
	}
}

func TestLoginWithAppRole_NonOKStatus(t *testing.T) {
	srv := newAppRoleMockServer(t, http.StatusForbidden, "", 0)
	defer srv.Close()

	c, err := NewClient(srv.URL, "ignored")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, err = c.LoginWithAppRole(AppRoleCredentials{RoleID: "bad-role", SecretID: "bad-secret"})
	if err == nil {
		t.Fatal("expected error for non-OK status, got nil")
	}
}

func TestLoginWithAppRole_EmptyRoleID(t *testing.T) {
	c, err := NewClient("http://127.0.0.1", "ignored")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, err = c.LoginWithAppRole(AppRoleCredentials{RoleID: "", SecretID: "s"})
	if err == nil {
		t.Fatal("expected error for empty role_id")
	}
}

func TestLoginWithAppRole_BadURL(t *testing.T) {
	c, err := NewClient("http://127.0.0.1:1", "ignored")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, err = c.LoginWithAppRole(AppRoleCredentials{RoleID: "r", SecretID: "s"})
	if err == nil {
		t.Fatal("expected connection error, got nil")
	}
}
