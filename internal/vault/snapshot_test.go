package vault

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newSnapshotMockServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sys/storage/raft/snapshot" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

func TestTakeSnapshot_Success(t *testing.T) {
	srv := newSnapshotMockServer(t, http.StatusOK, "snapshotdata")
	defer srv.Close()

	c := clientForTest(t, srv.URL)
	var buf bytes.Buffer
	status, err := c.TakeSnapshot(context.Background(), &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !status.Available {
		t.Error("expected Available=true")
	}
	if buf.String() != "snapshotdata" {
		t.Errorf("unexpected body: %q", buf.String())
	}
}

func TestTakeSnapshot_NotFound(t *testing.T) {
	srv := newSnapshotMockServer(t, http.StatusNotFound, "")
	defer srv.Close()

	c := clientForTest(t, srv.URL)
	var buf bytes.Buffer
	status, err := c.TakeSnapshot(context.Background(), &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.Available {
		t.Error("expected Available=false")
	}
}

func TestTakeSnapshot_NonOKStatus(t *testing.T) {
	srv := newSnapshotMockServer(t, http.StatusInternalServerError, "")
	defer srv.Close()

	c := clientForTest(t, srv.URL)
	var buf bytes.Buffer
	_, err := c.TakeSnapshot(context.Background(), &buf)
	if err == nil {
		t.Fatal("expected error for 500 status")
	}
}

func TestTakeSnapshot_BadURL(t *testing.T) {
	c := clientForTest(t, "http://127.0.0.1:0")
	var buf bytes.Buffer
	_, err := c.TakeSnapshot(context.Background(), &buf)
	if err == nil {
		t.Fatal("expected error for bad URL")
	}
}

func clientForTest(t *testing.T, addr string) *Client {
	t.Helper()
	return &Client{address: addr, token: "test-token", http: &http.Client{}}
}
