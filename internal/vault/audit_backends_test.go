package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newAuditMockServer(t *testing.T, status int, payload interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		if payload != nil {
			json.NewEncoder(w).Encode(payload)
		}
	}))
}

func TestListAuditBackends_Success(t *testing.T) {
	payload := map[string]interface{}{
		"file/": map[string]string{"type": "file", "description": "file audit"},
		"syslog/": map[string]string{"type": "syslog", "description": ""},
	}
	srv := newAuditMockServer(t, http.StatusOK, payload)
	defer srv.Close()

	c, _ := NewClient(srv.URL, "token")
	backends, err := c.ListAuditBackends()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(backends) != 2 {
		t.Fatalf("expected 2 backends, got %d", len(backends))
	}
	for _, b := range backends {
		if !b.Enabled {
			t.Errorf("expected backend %s to be enabled", b.Path)
		}
	}
}

func TestListAuditBackends_NonOKStatus(t *testing.T) {
	srv := newAuditMockServer(t, http.StatusForbidden, nil)
	defer srv.Close()

	c, _ := NewClient(srv.URL, "token")
	_, err := c.ListAuditBackends()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestListAuditBackends_BadURL(t *testing.T) {
	c, _ := NewClient("http://127.0.0.1:0", "token")
	_, err := c.ListAuditBackends()
	if err == nil {
		t.Fatal("expected error for bad URL")
	}
}
