package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newMockVaultServer(leaseDuration int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"lease_id":       "secret/data/test/abc123",
			"lease_duration": leaseDuration,
			"renewable":      true,
			"data": map[string]interface{}{
				"key": "value",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp) //nolint:errcheck
	}))
}

func TestNewClient_ValidConfig(t *testing.T) {
	srv := newMockVaultServer(3600)
	defer srv.Close()

	c, err := NewClient(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if c == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestGetSecretMeta_WithTTL(t *testing.T) {
	srv := newMockVaultServer(3600)
	defer srv.Close()

	c, err := NewClient(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	meta, err := c.GetSecretMeta(context.Background(), "secret/data/test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if meta.TTL != 3600*time.Second {
		t.Errorf("expected TTL 3600s, got %v", meta.TTL)
	}
	if meta.ExpiresAt.IsZero() {
		t.Error("expected non-zero ExpiresAt")
	}
}

func TestIsExpiringSoon(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name      string
		meta      SecretMeta
		threshold time.Duration
		want      bool
	}{
		{"expires within threshold", SecretMeta{ExpiresAt: now.Add(1 * time.Hour)}, 2 * time.Hour, true},
		{"expires outside threshold", SecretMeta{ExpiresAt: now.Add(5 * time.Hour)}, 2 * time.Hour, false},
		{"no expiry set", SecretMeta{ExpiresAt: time.Time{}}, 2 * time.Hour, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.meta.IsExpiringSoon(tc.threshold)
			if got != tc.want {
				t.Errorf("IsExpiringSoon() = %v, want %v", got, tc.want)
			}
		})
	}
}
