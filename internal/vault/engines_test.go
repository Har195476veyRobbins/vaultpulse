package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newEnginesMockServer(t *testing.T, status int, payload interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sys/mounts" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(status)
		if payload != nil {
			_ = json.NewEncoder(w).Encode(payload)
		}
	}))
}

func TestListSecretEngines_Success(t *testing.T) {
	payload := map[string]interface{}{
		"data": map[string]interface{}{
			"secret/": map[string]interface{}{
				"type":        "kv",
				"description": "key/value secrets",
				"accessor":    "kv_abc123",
			},
			"pki/": map[string]interface{}{
				"type":        "pki",
				"description": "PKI secrets engine",
				"accessor":    "pki_xyz789",
			},
		},
	}

	srv := newEnginesMockServer(t, http.StatusOK, payload)
	defer srv.Close()

	client := &Client{address: srv.URL, token: "test-token", http: srv.Client()}
	mounts, err := client.ListSecretEngines()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mounts) != 2 {
		t.Fatalf("expected 2 mounts, got %d", len(mounts))
	}

	types := map[string]bool{}
	for _, m := range mounts {
		types[m.Type] = true
	}
	if !types["kv"] || !types["pki"] {
		t.Errorf("expected kv and pki engine types, got %v", types)
	}
}

func TestListSecretEngines_NonOKStatus(t *testing.T) {
	srv := newEnginesMockServer(t, http.StatusForbidden, nil)
	defer srv.Close()

	client := &Client{address: srv.URL, token: "bad-token", http: srv.Client()}
	_, err := client.ListSecretEngines()
	if err == nil {
		t.Fatal("expected error for non-OK status, got nil")
	}
}

func TestListSecretEngines_BadURL(t *testing.T) {
	client := &Client{address: "http://127.0.0.1:0", token: "tok", http: &http.Client{}}
	_, err := client.ListSecretEngines()
	if err == nil {
		t.Fatal("expected error for bad URL, got nil")
	}
}
