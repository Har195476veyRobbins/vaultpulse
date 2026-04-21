package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTransitMockServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/transit/keys":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"keys": []string{"my-key", "another-key"},
				},
			})
		case "/v1/transit/keys/my-key":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"type":                   "aes256-gcm96",
					"deletion_allowed":        false,
					"exportable":              true,
					"min_decryption_version":  1,
					"min_encryption_version":  0,
					"latest_version":          3,
				},
			})
		case "/v1/transit/keys/missing":
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
}

func TestListTransitKeys_Success(t *testing.T) {
	srv := newTransitMockServer(t)
	defer srv.Close()

	c := &Client{address: srv.URL, token: "test-token", http: srv.Client()}
	keys, err := c.ListTransitKeys("transit")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}
	if keys[0] != "my-key" {
		t.Errorf("expected first key to be 'my-key', got %q", keys[0])
	}
}

func TestGetTransitKey_Success(t *testing.T) {
	srv := newTransitMockServer(t)
	defer srv.Close()

	c := &Client{address: srv.URL, token: "test-token", http: srv.Client()}
	info, err := c.GetTransitKey("transit", "my-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Type != "aes256-gcm96" {
		t.Errorf("expected type 'aes256-gcm96', got %q", info.Type)
	}
	if info.LatestVersion != 3 {
		t.Errorf("expected latest version 3, got %d", info.LatestVersion)
	}
	if !info.Exportable {
		t.Error("expected exportable to be true")
	}
}

func TestGetTransitKey_NotFound(t *testing.T) {
	srv := newTransitMockServer(t)
	defer srv.Close()

	c := &Client{address: srv.URL, token: "test-token", http: srv.Client()}
	_, err := c.GetTransitKey("transit", "missing")
	if err == nil {
		t.Fatal("expected error for missing key, got nil")
	}
}

func TestListTransitKeys_DefaultMount(t *testing.T) {
	srv := newTransitMockServer(t)
	defer srv.Close()

	c := &Client{address: srv.URL, token: "test-token", http: srv.Client()}
	// empty mount should default to "transit"
	keys, err := c.ListTransitKeys("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}
}

func TestListTransitKeys_BadURL(t *testing.T) {
	c := &Client{address: "http://127.0.0.1:0", token: "test-token", http: http.DefaultClient}
	_, err := c.ListTransitKeys("transit")
	if err == nil {
		t.Fatal("expected error for bad URL, got nil")
	}
}
