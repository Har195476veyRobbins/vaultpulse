package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newHealthMockServer(t *testing.T, statusCode int, body map[string]interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/sys/health", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		_ = json.NewEncoder(w).Encode(body)
	}))
}

func TestCheckHealth_Healthy(t *testing.T) {
	srv := newHealthMockServer(t, http.StatusOK, map[string]interface{}{
		"initialized":  true,
		"sealed":       false,
		"standby":      false,
		"version":      "1.15.0",
		"cluster_name": "vault-cluster-dev",
	})
	defer srv.Close()

	client := clientForURL(t, srv.URL)
	status, err := client.CheckHealth(context.Background())

	require.NoError(t, err)
	assert.True(t, status.Initialized)
	assert.False(t, status.Sealed)
	assert.False(t, status.Standby)
	assert.Equal(t, "1.15.0", status.Version)
	assert.Equal(t, "vault-cluster-dev", status.ClusterName)
	assert.True(t, status.IsHealthy())
	assert.False(t, status.CheckedAt.IsZero())
}

func TestCheckHealth_Sealed(t *testing.T) {
	srv := newHealthMockServer(t, http.StatusServiceUnavailable, map[string]interface{}{
		"initialized": true,
		"sealed":      true,
		"standby":     false,
		"version":     "1.15.0",
	})
	defer srv.Close()

	client := clientForURL(t, srv.URL)
	status, err := client.CheckHealth(context.Background())

	require.NoError(t, err)
	assert.True(t, status.Sealed)
	assert.False(t, status.IsHealthy())
}

func TestCheckHealth_Standby(t *testing.T) {
	srv := newHealthMockServer(t, 429, map[string]interface{}{
		"initialized": true,
		"sealed":      false,
		"standby":     true,
		"version":     "1.15.0",
	})
	defer srv.Close()

	client := clientForURL(t, srv.URL)
	status, err := client.CheckHealth(context.Background())

	require.NoError(t, err)
	assert.True(t, status.Standby)
	assert.False(t, status.IsHealthy())
}

func TestCheckHealth_BadURL(t *testing.T) {
	client := clientForURL(t, "http://127.0.0.1:0")
	_, err := client.CheckHealth(context.Background())
	require.Error(t, err)
}

// clientForURL is a helper that constructs a Client pointing at the given URL.
func clientForURL(t *testing.T, url string) *Client {
	t.Helper()
	c := &Client{
		address:    url,
		httpClient: &http.Client{},
	}
	return c
}
