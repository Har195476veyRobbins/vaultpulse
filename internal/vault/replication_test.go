package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newReplicationMockServer(t *testing.T, status int, body interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		if body != nil {
			_ = json.NewEncoder(w).Encode(body)
		}
	}))
}

func TestGetReplicationStatus_Success(t *testing.T) {
	payload := map[string]interface{}{
		"data": map[string]interface{}{
			"dr":          map[string]string{"mode": "primary", "state": "running"},
			"performance": map[string]string{"mode": "disabled", "state": ""},
		},
	}
	srv := newReplicationMockServer(t, http.StatusOK, payload)
	defer srv.Close()

	c := &Client{address: srv.URL, token: "test-token", http: srv.Client()}
	rs, err := c.GetReplicationStatus(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rs.DR.Mode != "primary" {
		t.Errorf("expected DR mode primary, got %s", rs.DR.Mode)
	}
	if rs.Performance.Mode != "disabled" {
		t.Errorf("expected performance mode disabled, got %s", rs.Performance.Mode)
	}
}

func TestGetReplicationStatus_NonOKStatus(t *testing.T) {
	srv := newReplicationMockServer(t, http.StatusForbidden, nil)
	defer srv.Close()

	c := &Client{address: srv.URL, token: "bad-token", http: srv.Client()}
	_, err := c.GetReplicationStatus(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestGetReplicationStatus_BadURL(t *testing.T) {
	c := &Client{address: "http://127.0.0.1:0", token: "t", http: &http.Client{}}
	_, err := c.GetReplicationStatus(context.Background())
	if err == nil {
		t.Fatal("expected error for bad URL")
	}
}
