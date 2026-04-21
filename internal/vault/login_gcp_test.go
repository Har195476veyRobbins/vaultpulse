package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newGCPMockServer(t *testing.T, statusCode int, payload interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		if payload != nil {
			_ = json.NewEncoder(w).Encode(payload)
		}
	}))
}

func TestLoginWithGCP_Success(t *testing.T) {
	payload := GCPLoginResponse{}
	payload.Auth.ClientToken = "gcp-token-abc"
	payload.Auth.LeaseDuration = 3600
	payload.Auth.Renewable = true

	srv := newGCPMockServer(t, http.StatusOK, payload)
	defer srv.Close()

	client := newTestClient(t, srv.URL)
	resp, err := client.LoginWithGCP("my-role", "signed-jwt", "gcp")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if resp.Auth.ClientToken != "gcp-token-abc" {
		t.Errorf("expected token gcp-token-abc, got %s", resp.Auth.ClientToken)
	}
}

func TestLoginWithGCP_Forbidden(t *testing.T) {
	srv := newGCPMockServer(t, http.StatusForbidden, nil)
	defer srv.Close()

	client := newTestClient(t, srv.URL)
	_, err := client.LoginWithGCP("my-role", "signed-jwt", "gcp")
	if err == nil {
		t.Fatal("expected error for 403 status")
	}
}

func TestLoginWithGCP_EmptyRole(t *testing.T) {
	client := newTestClient(t, "http://127.0.0.1")
	_, err := client.LoginWithGCP("", "signed-jwt", "gcp")
	if err == nil {
		t.Fatal("expected error for empty role")
	}
}

func TestLoginWithGCP_EmptyJWT(t *testing.T) {
	client := newTestClient(t, "http://127.0.0.1")
	_, err := client.LoginWithGCP("my-role", "", "gcp")
	if err == nil {
		t.Fatal("expected error for empty jwt")
	}
}

func TestLoginWithGCP_BadURL(t *testing.T) {
	client := newTestClient(t, "http://127.0.0.1:0")
	_, err := client.LoginWithGCP("my-role", "signed-jwt", "gcp")
	if err == nil {
		t.Fatal("expected error for bad URL")
	}
}
