package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newKubernetesMockServer(t *testing.T, status int, token string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		if status == http.StatusOK {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"auth": map[string]string{"client_token": token},
			})
		}
	}))
}

func TestLoginWithKubernetes_Success(t *testing.T) {
	srv := newKubernetesMockServer(t, http.StatusOK, "k8s-token-abc")
	defer srv.Close()
	c := &Client{Address: srv.URL, HTTP: srv.Client()}
	tok, err := c.LoginWithKubernetes("my-role", "jwt-value", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "k8s-token-abc" {
		t.Errorf("expected k8s-token-abc, got %s", tok)
	}
}

func TestLoginWithKubernetes_Forbidden(t *testing.T) {
	srv := newKubernetesMockServer(t, http.StatusForbidden, "")
	defer srv.Close()
	c := &Client{Address: srv.URL, HTTP: srv.Client()}
	_, err := c.LoginWithKubernetes("role", "jwt", "kubernetes")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestLoginWithKubernetes_EmptyRole(t *testing.T) {
	c := &Client{Address: "http://localhost", HTTP: http.DefaultClient}
	_, err := c.LoginWithKubernetes("", "jwt", "")
	if err == nil {
		t.Fatal("expected error for empty role")
	}
}

func TestLoginWithKubernetes_EmptyJWT(t *testing.T) {
	c := &Client{Address: "http://localhost", HTTP: http.DefaultClient}
	_, err := c.LoginWithKubernetes("role", "", "")
	if err == nil {
		t.Fatal("expected error for empty jwt")
	}
}

func TestLoginWithKubernetes_BadURL(t *testing.T) {
	c := &Client{Address: "http://127.0.0.1:0", HTTP: http.DefaultClient}
	_, err := c.LoginWithKubernetes("role", "jwt", "")
	if err == nil {
		t.Fatal("expected connection error")
	}
}
