package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newAzureMockServer(t *testing.T, statusCode int, token string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/azure/login" || r.Method != http.MethodPost {
			http.NotFound(w, r)
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

func TestLoginWithAzure_Success(t *testing.T) {
	srv := newAzureMockServer(t, http.StatusOK, "azure-token-xyz")
	defer srv.Close()

	c := newTestClientFromURL(t, srv.URL)
	resp, err := c.LoginWithAzure(AzureLoginRequest{
		Role:              "my-role",
		JWT:               "eyJ...",
		SubscriptionID:    "sub-123",
		ResourceGroupName: "rg-prod",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.ClientToken != "azure-token-xyz" {
		t.Errorf("expected token 'azure-token-xyz', got %q", resp.ClientToken)
	}
	if !resp.Renewable {
		t.Error("expected renewable to be true")
	}
}

func TestLoginWithAzure_Forbidden(t *testing.T) {
	srv := newAzureMockServer(t, http.StatusForbidden, "")
	defer srv.Close()

	c := newTestClientFromURL(t, srv.URL)
	_, err := c.LoginWithAzure(AzureLoginRequest{
		Role:              "bad-role",
		JWT:               "eyJ...",
		SubscriptionID:    "sub-123",
		ResourceGroupName: "rg-prod",
	})
	if err == nil {
		t.Fatal("expected error for forbidden, got nil")
	}
}

func TestLoginWithAzure_EmptyRole(t *testing.T) {
	c := newTestClientFromURL(t, "http://127.0.0.1")
	_, err := c.LoginWithAzure(AzureLoginRequest{
		JWT:               "eyJ...",
		SubscriptionID:    "sub-123",
		ResourceGroupName: "rg-prod",
	})
	if err == nil {
		t.Fatal("expected error for empty role")
	}
}

func TestLoginWithAzure_EmptyJWT(t *testing.T) {
	c := newTestClientFromURL(t, "http://127.0.0.1")
	_, err := c.LoginWithAzure(AzureLoginRequest{
		Role:              "my-role",
		SubscriptionID:    "sub-123",
		ResourceGroupName: "rg-prod",
	})
	if err == nil {
		t.Fatal("expected error for empty jwt")
	}
}

func TestLoginWithAzure_BadURL(t *testing.T) {
	c := newTestClientFromURL(t, "http://127.0.0.1:0")
	_, err := c.LoginWithAzure(AzureLoginRequest{
		Role:              "my-role",
		JWT:               "eyJ...",
		SubscriptionID:    "sub-123",
		ResourceGroupName: "rg-prod",
	})
	if err == nil {
		t.Fatal("expected error for bad URL")
	}
}
