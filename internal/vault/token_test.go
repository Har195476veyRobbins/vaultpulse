package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTokenMockServer(t *testing.T, statusCode int, payload interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/auth/token/lookup-self", r.URL.Path)
		assert.Equal(t, "test-token", r.Header.Get("X-Vault-Token"))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		_ = json.NewEncoder(w).Encode(payload)
	}))
}

func TestLookupSelfToken_Success(t *testing.T) {
	expire := time.Now().Add(2 * time.Hour).UTC().Truncate(time.Second)
	payload := map[string]interface{}{
		"data": map[string]interface{}{
			"accessor":     "abc123",
			"display_name": "token-test",
			"policies":     []string{"default", "read-secrets"},
			"ttl":          7200,
			"renewable":    true,
			"expire_time":  expire.Format(time.RFC3339),
		},
	}

	srv := newTokenMockServer(t, http.StatusOK, payload)
	defer srv.Close()

	client, err := NewClient(srv.URL, "test-token")
	require.NoError(t, err)

	info, err := client.LookupSelfToken(context.Background())
	require.NoError(t, err)

	assert.Equal(t, "abc123", info.Accessor)
	assert.Equal(t, "token-test", info.DisplayName)
	assert.Equal(t, []string{"default", "read-secrets"}, info.Policies)
	assert.Equal(t, 2*time.Hour, info.TTL)
	assert.True(t, info.Renewable)
	assert.Equal(t, expire, info.ExpireTime)
}

func TestLookupSelfToken_NonOKStatus(t *testing.T) {
	srv := newTokenMockServer(t, http.StatusForbidden, map[string]string{"errors": "permission denied"})
	defer srv.Close()

	client, err := NewClient(srv.URL, "test-token")
	require.NoError(t, err)

	_, err = client.LookupSelfToken(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
}

func TestLookupSelfToken_BadURL(t *testing.T) {
	client, err := NewClient("http://127.0.0.1:0", "test-token")
	require.NoError(t, err)

	_, err = client.LookupSelfToken(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token lookup request")
}

func TestLookupSelfToken_NoExpireTime(t *testing.T) {
	payload := map[string]interface{}{
		"data": map[string]interface{}{
			"accessor":     "xyz",
			"display_name": "root",
			"policies":     []string{"root"},
			"ttl":          0,
			"renewable":    false,
			"expire_time":  "",
		},
	}

	srv := newTokenMockServer(t, http.StatusOK, payload)
	defer srv.Close()

	client, err := NewClient(srv.URL, "test-token")
	require.NoError(t, err)

	info, err := client.LookupSelfToken(context.Background())
	require.NoError(t, err)
	assert.True(t, info.ExpireTime.IsZero())
}
