package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newNamespaceMockServer(t *testing.T, status int, body interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if body != nil {
			_ = json.NewEncoder(w).Encode(body)
		}
	}))
}

func TestListNamespaces_Success(t *testing.T) {
	body := map[string]interface{}{
		"data": map[string]interface{}{
			"key_info": map[string]interface{}{
				"ns1/": map[string]interface{}{"path": "ns1/", "id": "abc123", "custom_metadata": map[string]string{}},
				"ns2/": map[string]interface{}{"path": "ns2/", "id": "def456", "custom_metadata": map[string]string{}},
			},
		},
	}
	srv := newNamespaceMockServer(t, http.StatusOK, body)
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	ns, err := c.ListNamespaces()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ns) != 2 {
		t.Errorf("expected 2 namespaces, got %d", len(ns))
	}
}

func TestListNamespaces_NotFound(t *testing.T) {
	srv := newNamespaceMockServer(t, http.StatusNotFound, nil)
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_, err := c.ListNamespaces()
	if err == nil {
		t.Fatal("expected error for 404, got nil")
	}
}

func TestListNamespaces_NonOKStatus(t *testing.T) {
	srv := newNamespaceMockServer(t, http.StatusForbidden, nil)
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_, err := c.ListNamespaces()
	if err == nil {
		t.Fatal("expected error for non-OK status")
	}
}

func TestListNamespaces_BadURL(t *testing.T) {
	c := newTestClient(t, "http://127.0.0.1:0")
	_, err := c.ListNamespaces()
	if err == nil {
		t.Fatal("expected error for bad URL")
	}
}

func newTestClient(t *testing.T, addr string) *Client {
	t.Helper()
	c, err := NewClient(addr, "test-token")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}
