package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newQuotaMockServer(t *testing.T, status int, keys []string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		if status == http.StatusOK {
			body := map[string]interface{}{
				"data": map[string]interface{}{"keys": keys},
			}
			_ = json.NewEncoder(w).Encode(body)
		}
	}))
}

func TestListQuotas_Success(t *testing.T) {
	srv := newQuotaMockServer(t, http.StatusOK, []string{"global-rate", "kv-rate"})
	defer srv.Close()

	c := &Client{address: srv.URL, token: "tok", http: srv.Client()}
	keys, err := c.ListQuotas()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}
}

func TestListQuotas_NotFound(t *testing.T) {
	srv := newQuotaMockServer(t, http.StatusNotFound, nil)
	defer srv.Close()

	c := &Client{address: srv.URL, token: "tok", http: srv.Client()}
	keys, err := c.ListQuotas()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("expected empty slice")
	}
}

func TestListQuotas_NonOKStatus(t *testing.T) {
	srv := newQuotaMockServer(t, http.StatusForbidden, nil)
	defer srv.Close()

	c := &Client{address: srv.URL, token: "tok", http: srv.Client()}
	_, err := c.ListQuotas()
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestListQuotas_BadURL(t *testing.T) {
	c := &Client{address: "http://127.0.0.1:1", token: "tok", http: &http.Client{}}
	_, err := c.ListQuotas()
	if err == nil {
		t.Fatal("expected error for bad URL")
	}
}
