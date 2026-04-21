package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newGitHubMockServer(t *testing.T, status int, body any) (*httptest.Server, *Client) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if body != nil {
			_ = json.NewEncoder(w).Encode(body)
		}
	}))
	t.Cleanup(srv.Close)
	client, err := NewClient(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return srv, client
}

func TestLoginWithGitHub_Success(t *testing.T) {
	body := map[string]any{
		"auth": map[string]any{
			"client_token":   "s.github-token",
			"lease_duration": 3600,
			"renewable":      true,
		},
	}
	_, client := newGitHubMockServer(t, http.StatusOK, body)

	resp, err := client.LoginWithGitHub("ghp_validtoken")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Auth.ClientToken != "s.github-token" {
		t.Errorf("expected client_token s.github-token, got %s", resp.Auth.ClientToken)
	}
	if !resp.Auth.Renewable {
		t.Error("expected renewable to be true")
	}
}

func TestLoginWithGitHub_Forbidden(t *testing.T) {
	_, client := newGitHubMockServer(t, http.StatusForbidden, nil)

	_, err := client.LoginWithGitHub("ghp_badtoken")
	if err == nil {
		t.Fatal("expected error for forbidden, got nil")
	}
}

func TestLoginWithGitHub_EmptyToken(t *testing.T) {
	_, client := newGitHubMockServer(t, http.StatusOK, nil)

	_, err := client.LoginWithGitHub("")
	if err == nil {
		t.Fatal("expected error for empty token, got nil")
	}
}

func TestLoginWithGitHub_BadURL(t *testing.T) {
	client, err := NewClient("http://127.0.0.1:0", "test-token")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.LoginWithGitHub("ghp_sometoken")
	if err == nil {
		t.Fatal("expected error for bad URL, got nil")
	}
}

func TestLoginWithGitHub_NonOKStatus(t *testing.T) {
	_, client := newGitHubMockServer(t, http.StatusInternalServerError, nil)

	_, err := client.LoginWithGitHub("ghp_sometoken")
	if err == nil {
		t.Fatal("expected error for non-OK status, got nil")
	}
}
