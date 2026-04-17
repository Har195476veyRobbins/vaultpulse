package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newRaftMockServer(t *testing.T, status int, body interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		if body != nil {
			_ = json.NewEncoder(w).Encode(body)
		}
	}))
}

func TestGetRaftStatus_Success(t *testing.T) {
	payload := map[string]interface{}{
		"data": map[string]interface{}{
			"servers": []map[string]interface{}{
				{"node_id": "node1", "address": "127.0.0.1:8201", "leader": true, "voter": true, "protocol_version": "3"},
				{"node_id": "node2", "address": "127.0.0.1:8202", "leader": false, "voter": true, "protocol_version": "3"},
			},
		},
	}
	srv := newRaftMockServer(t, http.StatusOK, payload)
	defer srv.Close()

	c := &Client{address: srv.URL, token: "test-token", http: srv.Client()}
	rs, err := c.GetRaftStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rs.Servers) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(rs.Servers))
	}
	if !rs.Servers[0].Leader {
		t.Error("expected first server to be leader")
	}
}

func TestGetRaftStatus_NonOKStatus(t *testing.T) {
	srv := newRaftMockServer(t, http.StatusForbidden, nil)
	defer srv.Close()

	c := &Client{address: srv.URL, token: "bad-token", http: srv.Client()}
	_, err := c.GetRaftStatus()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestGetRaftStatus_BadURL(t *testing.T) {
	c := &Client{address: "http://127.0.0.1:0", token: "t", http: &http.Client{}}
	_, err := c.GetRaftStatus()
	if err == nil {
		t.Fatal("expected error for bad URL")
	}
}
