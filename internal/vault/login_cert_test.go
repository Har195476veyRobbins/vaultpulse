package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newCertMockServer(t *testing.T, status int, token string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/cert/login" {
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

func TestLoginWithCert_Success(t *testing.T) {
	srv := newCertMockServer(t, http.StatusOK, "cert-token-abc")
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	resp, err := c.LoginWithCert(CertLoginRequest{CertRoleName: "web"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.ClientToken != "cert-token-abc" {
		t.Errorf("expected cert-token-abc, got %s", resp.ClientToken)
	}
	if resp.LeaseDuration != 3600 {
		t.Errorf("expected 3600, got %d", resp.LeaseDuration)
	}
}

func TestLoginWithCert_Forbidden(t *testing.T) {
	srv := newCertMockServer(t, http.StatusForbidden, "")
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_, err := c.LoginWithCert(CertLoginRequest{CertRoleName: "web"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestLoginWithCert_EmptyRoleName(t *testing.T) {
	c := &Client{address: "http://localhost", http: &http.Client{}}
	_, err := c.LoginWithCert(CertLoginRequest{})
	if err == nil {
		t.Fatal("expected error for empty role name")
	}
}

func TestLoginWithCert_BadURL(t *testing.T) {
	c := &Client{address: "http://127.0.0.1:0", http: &http.Client{}}
	_, err := c.LoginWithCert(CertLoginRequest{CertRoleName: "web"})
	if err == nil {
		t.Fatal("expected error for bad URL")
	}
}
