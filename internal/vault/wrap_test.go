package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newWrapMockServer(t *testing.T, status int, body interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if body != nil {
			_ = json.NewEncoder(w).Encode(body)
		}
	}))
}

func TestLookupWrappingToken_Success(t *testing.T) {
	payload := map[string]interface{}{
		"data": map[string]interface{}{
			"token":           "wrapping-token-abc",
			"accessor":        "acc-123",
			"ttl":             300,
			"creation_time":   time.Now().UTC(),
			"creation_path":   "auth/approle/login",
			"wrapped_accessor": "wacc-456",
		},
	}
	srv := newWrapMockServer(t, http.StatusOK, payload)
	defer srv.Close()

	c := &Client{address: srv.URL, http: srv.Client()}
	info, err := c.LookupWrappingToken("wrapping-token-abc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.CreationPath != "auth/approle/login" {
		t.Errorf("expected creation_path 'auth/approle/login', got %q", info.CreationPath)
	}
	if info.TTL != 300 {
		t.Errorf("expected TTL 300, got %d", info.TTL)
	}
}

func TestLookupWrappingToken_EmptyToken(t *testing.T) {
	c := &Client{address: "http://127.0.0.1", http: http.DefaultClient}
	_, err := c.LookupWrappingToken("")
	if err == nil {
		t.Fatal("expected error for empty token")
	}
}

func TestLookupWrappingToken_NotFound(t *testing.T) {
	srv := newWrapMockServer(t, http.StatusNotFound, nil)
	defer srv.Close()

	c := &Client{address: srv.URL, http: srv.Client()}
	_, err := c.LookupWrappingToken("expired-token")
	if err == nil {
		t.Fatal("expected error for 404")
	}
}

func TestLookupWrappingToken_NonOKStatus(t *testing.T) {
	srv := newWrapMockServer(t, http.StatusForbidden, nil)
	defer srv.Close()

	c := &Client{address: srv.URL, http: srv.Client()}
	_, err := c.LookupWrappingToken("some-token")
	if err == nil {
		t.Fatal("expected error for non-OK status")
	}
}
