package vault_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/arnavsurve/vaultpulse/internal/vault"
)

func newMountsMockServer(t *testing.T, status int, body any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sys/mounts" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}))
}

func TestListMounts_Success(t *testing.T) {
	payload := map[string]vault.MountInfo{
		"secret/": {Type: "kv", Description: "key/value secrets", Accessor: "kv_abc123"},
		"pki/":    {Type: "pki", Description: "PKI secrets", Accessor: "pki_def456"},
	}
	srv := newMountsMockServer(t, http.StatusOK, payload)
	defer srv.Close()

	c, err := vault.NewClient(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	mounts, err := c.ListMounts()
	if err != nil {
		t.Fatalf("ListMounts: %v", err)
	}
	if len(mounts) != 2 {
		t.Fatalf("expected 2 mounts, got %d", len(mounts))
	}
	if mounts["secret/"].Type != "kv" {
		t.Errorf("expected type kv, got %s", mounts["secret/"].Type)
	}
}

func TestListMounts_NonOKStatus(t *testing.T) {
	srv := newMountsMockServer(t, http.StatusForbidden, nil)
	defer srv.Close()

	c, err := vault.NewClient(srv.URL, "bad-token")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, err = c.ListMounts()
	if err == nil {
		t.Fatal("expected error for non-OK status")
	}
}

func TestListMounts_BadURL(t *testing.T) {
	c, err := vault.NewClient("http://127.0.0.1:0", "token")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = c.ListMounts()
	if err == nil {
		t.Fatal("expected error for bad URL")
	}
}
