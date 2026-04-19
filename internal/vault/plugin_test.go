package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newPluginMockServer(t *testing.T, status int, plugins []PluginInfo) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		if status == http.StatusOK {
			body := map[string]interface{}{
				"data": map[string]interface{}{"detailed": plugins},
			}
			_ = json.NewEncoder(w).Encode(body)
		}
	}))
}

func TestListPlugins_Success(t *testing.T) {
	plugins := []PluginInfo{
		{Name: "aws", Type: "secret", Version: "v1.0.0", Builtin: true},
		{Name: "custom-auth", Type: "auth", Version: "v0.2.1", Builtin: false},
	}
	srv := newPluginMockServer(t, http.StatusOK, plugins)
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	got, err := c.ListPlugins()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 plugins, got %d", len(got))
	}
	if got[0].Name != "aws" {
		t.Errorf("expected aws, got %s", got[0].Name)
	}
}

func TestListPlugins_NonOKStatus(t *testing.T) {
	srv := newPluginMockServer(t, http.StatusForbidden, nil)
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_, err := c.ListPlugins()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestListPlugins_BadURL(t *testing.T) {
	c := newTestClient(t, "http://127.0.0.1:0")
	_, err := c.ListPlugins()
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
