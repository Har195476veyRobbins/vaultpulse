package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTLSLoginMockServer(t *testing.T, statusCode int, token string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(statusCode)
		if statusCode == http.StatusOK {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token":   token,
					"lease_duration": 3600,
					"renewable":      true,
				},
			})
		}
	}))
}

func TestLoginWithTLS_MissingCert(t *testing.T) {
	srv := newTLSLoginMockServer(t, http.StatusOK, "tls-token")
	defer srv.Close()

	c := newTestVaultClient(t, srv.URL)
	_, err := c.LoginWithTLS(context.Background(), TLSLoginRequest{})
	if err == nil {
		t.Fatal("expected error for missing cert/key, got nil")
	}
}

func TestLoginWithTLS_BadURL(t *testing.T) {
	c := newTestVaultClient(t, "http://127.0.0.1:0")
	// provide dummy PEM bytes so we pass the validation check
	_, err := c.LoginWithTLS(context.Background(), TLSLoginRequest{
		CertPEM: []byte("bad"),
		KeyPEM:  []byte("bad"),
	})
	if err == nil {
		t.Fatal("expected error for bad URL, got nil")
	}
}

func TestLoginWithTLS_NonOKStatus(t *testing.T) {
	srv := newTLSLoginMockServer(t, http.StatusForbidden, "")
	defer srv.Close()

	c := newTestVaultClient(t, srv.URL)
	_, err := c.LoginWithTLS(context.Background(), TLSLoginRequest{
		CertPEM: []byte("bad"),
		KeyPEM:  []byte("bad"),
	})
	if err == nil {
		t.Fatal("expected error for forbidden status, got nil")
	}
}

func newTestVaultClient(t *testing.T, addr string) *Client {
	t.Helper()
	c, err := NewClient(ClientConfig{Address: addr, Token: "test-token"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}
