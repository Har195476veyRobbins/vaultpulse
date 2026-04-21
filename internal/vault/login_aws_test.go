package vault_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yourusername/vaultpulse/internal/vault"
)

func newAWSMockServer(t *testing.T, status int, token string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/aws/login" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
		if token != "" {
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

func TestLoginWithAWS_Success(t *testing.T) {
	srv := newAWSMockServer(t, http.StatusOK, "aws-token-abc")
	defer srv.Close()

	client := &vault.Client{Address: srv.URL, HTTP: srv.Client()}
	tok, err := client.LoginWithAWS(vault.AWSLoginRequest{
		Role:                 "my-role",
		IAMHTTPRequestMethod: "POST",
		IAMRequestURL:        "aHR0cHM6Ly9zdHMuYW1hem9uYXdzLmNvbS8=",
		IAMRequestBody:       "QWN0aW9uPUdldENhbGxlcklkZW50aXR5",
		IAMRequestHeaders:    "{}",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if tok != "aws-token-abc" {
		t.Errorf("expected token 'aws-token-abc', got %q", tok)
	}
}

func TestLoginWithAWS_Forbidden(t *testing.T) {
	srv := newAWSMockServer(t, http.StatusForbidden, "")
	defer srv.Close()

	client := &vault.Client{Address: srv.URL, HTTP: srv.Client()}
	_, err := client.LoginWithAWS(vault.AWSLoginRequest{
		Role:          "bad-role",
		IAMRequestURL: "aHR0cHM6Ly9zdHMuYW1hem9uYXdzLmNvbS8=",
	})
	if err == nil {
		t.Fatal("expected error for forbidden status, got nil")
	}
}

func TestLoginWithAWS_EmptyRole(t *testing.T) {
	client := &vault.Client{Address: "http://127.0.0.1", HTTP: http.DefaultClient}
	_, err := client.LoginWithAWS(vault.AWSLoginRequest{
		IAMRequestURL: "aHR0cHM6Ly9zdHMuYW1hem9uYXdzLmNvbS8=",
	})
	if err == nil {
		t.Fatal("expected error for empty role, got nil")
	}
}

func TestLoginWithAWS_EmptyRequestURL(t *testing.T) {
	client := &vault.Client{Address: "http://127.0.0.1", HTTP: http.DefaultClient}
	_, err := client.LoginWithAWS(vault.AWSLoginRequest{Role: "my-role"})
	if err == nil {
		t.Fatal("expected error for empty iam_request_url, got nil")
	}
}

func TestLoginWithAWS_BadURL(t *testing.T) {
	client := &vault.Client{Address: "http://127.0.0.1:0", HTTP: http.DefaultClient}
	_, err := client.LoginWithAWS(vault.AWSLoginRequest{
		Role:          "my-role",
		IAMRequestURL: "aHR0cHM6Ly9zdHMuYW1hem9uYXdzLmNvbS8=",
	})
	if err == nil {
		t.Fatal("expected connection error, got nil")
	}
}
