package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newOCIMockServer(t *testing.T, statusCode int, body interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		if body != nil {
			_ = json.NewEncoder(w).Encode(body)
		}
	}))
}

func TestLoginWithOCI_Success(t *testing.T) {
	response := map[string]interface{}{
		"auth": map[string]interface{}{
			"client_token":   "oci-token-abc",
			"lease_duration": 3600,
			"renewable":      true,
		},
	}
	srv := newOCIMockServer(t, http.StatusOK, response)
	defer srv.Close()

	client := &Client{address: srv.URL}
	resp, err := client.LoginWithOCI(context.Background(), OCILoginRequest{
		Role:       "my-role",
		RequestURL: "https://example.com/request",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if resp.ClientToken != "oci-token-abc" {
		t.Errorf("expected client_token 'oci-token-abc', got %q", resp.ClientToken)
	}
	if resp.LeaseDuration != 3600 {
		t.Errorf("expected lease_duration 3600, got %d", resp.LeaseDuration)
	}
	if !resp.Renewable {
		t.Error("expected renewable to be true")
	}
}

func TestLoginWithOCI_Forbidden(t *testing.T) {
	srv := newOCIMockServer(t, http.StatusForbidden, nil)
	defer srv.Close()

	client := &Client{address: srv.URL}
	_, err := client.LoginWithOCI(context.Background(), OCILoginRequest{
		Role:       "my-role",
		RequestURL: "https://example.com/request",
	})
	if err == nil {
		t.Fatal("expected error for forbidden, got nil")
	}
}

func TestLoginWithOCI_EmptyRole(t *testing.T) {
	client := &Client{address: "http://127.0.0.1"}
	_, err := client.LoginWithOCI(context.Background(), OCILoginRequest{
		Role:       "",
		RequestURL: "https://example.com/request",
	})
	if err == nil {
		t.Fatal("expected error for empty role, got nil")
	}
}

func TestLoginWithOCI_EmptyRequestURL(t *testing.T) {
	client := &Client{address: "http://127.0.0.1"}
	_, err := client.LoginWithOCI(context.Background(), OCILoginRequest{
		Role:       "my-role",
		RequestURL: "",
	})
	if err == nil {
		t.Fatal("expected error for empty request_url, got nil")
	}
}

func TestLoginWithOCI_BadURL(t *testing.T) {
	client := &Client{address: "http://127.0.0.1:0"}
	_, err := client.LoginWithOCI(context.Background(), OCILoginRequest{
		Role:       "my-role",
		RequestURL: "https://example.com/request",
	})
	if err == nil {
		t.Fatal("expected error for bad URL, got nil")
	}
}
