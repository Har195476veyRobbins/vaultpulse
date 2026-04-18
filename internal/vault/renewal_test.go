package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
)

func newRenewalMockServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/secret/data/myapp/db":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"data": map[string]interface{}{"password": "s3cr3t"},
					"metadata": map[string]interface{}{
						"deletion_time": "",
					},
				},
				"lease_id":       "database/creds/myapp/abc123",
				"lease_duration": 3600,
				"renewable":      true,
			})
		case "/v1/sys/leases/renew":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"lease_id":       "database/creds/myapp/abc123",
				"lease_duration": 7200,
				"renewable":      true,
			})
		case "/v1/secret/data/nolease":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"data": map[string]interface{}{"key": "val"},
					"metadata": map[string]interface{}{"deletion_time": ""},
				},
				"lease_id":       "",
				"lease_duration": 0,
				"renewable":      false,
			})
		default:
			http.NotFound(w, r)
		}
	}))
}

// newRenewalClient is a helper that creates a Client pointed at the given test server URL.
func newRenewalClient(t *testing.T, serverURL string) *Client {
	t.Helper()
	cfg := api.DefaultConfig()
	cfg.Address = serverURL
	client, err := NewClient(cfg, "test-token")
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	return client
}

func TestRenewLease_Success(t *testing.T) {
	srv := newRenewalMockServer(t)
	defer srv.Close()

	client := newRenewalClient(t, srv.URL)

	result := client.RenewLease(context.Background(), "secret/data/myapp/db", 2*time.Hour)
	if result.Err != nil {
		t.Fatalf("unexpected error: %v", result.Err)
	}
	if !result.Renewed {
		t.Error("expected Renewed to be true")
	}
	if result.NewTTL != 7200*time.Second {
		t.Errorf("expected NewTTL 7200s, got %v", result.NewTTL)
	}
}

func TestRenewLease_NoLeaseID(t *testing.T) {
	srv := newRenewalMockServer(t)
	defer srv.Close()

	client := newRenewalClient(t, srv.URL)

	result := client.RenewLease(context.Background(), "secret/data/nolease", time.Hour)
	if result.Err == nil {
		t.Fatal("expected error for missing lease ID")
	}
	if result.Renewed {
		t.Error("expected Renewed to be false")
	}
}

func TestRenewLease_PathNotFound(t *testing.T) {
	srv := newRenewalMockServer(t)
	defer srv.Close()

	client := newRenewalClient(t, srv.URL)

	result := client.RenewLease(context.Background(), "secret/data/missing", time.Hour)
	if result.Err == nil {
		t.Fatal("expected error for unknown path")
	}
}
