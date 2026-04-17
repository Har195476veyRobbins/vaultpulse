package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newLeaseMockServer(t *testing.T, leaseID string, ttl int, expireTime string, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"id":          leaseID,
				"renewable":   true,
				"ttl":         ttl,
				"expire_time": expireTime,
			},
		})
	}))
}

func TestLookupLease_Success(t *testing.T) {
	expire := time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)
	srv := newLeaseMockServer(t, "lease/abc", 7200, expire, http.StatusOK)
	defer srv.Close()

	c := clientForTest(t, srv.URL)
	info, err := c.LookupLease(context.Background(), "lease/abc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.LeaseID != "lease/abc" {
		t.Errorf("expected lease id lease/abc, got %s", info.LeaseID)
	}
	if !info.Renewable {
		t.Error("expected renewable to be true")
	}
	if info.LeaseDuration != 7200*time.Second {
		t.Errorf("unexpected duration: %v", info.LeaseDuration)
	}
}

func TestLookupLease_EmptyID(t *testing.T) {
	c := clientForTest(t, "http://localhost")
	_, err := c.LookupLease(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty lease id")
	}
}

func TestLookupLease_NotFound(t *testing.T) {
	srv := newLeaseMockServer(t, "", 0, "", http.StatusNotFound)
	defer srv.Close()

	c := clientForTest(t, srv.URL)
	_, err := c.LookupLease(context.Background(), "lease/missing")
	if err == nil {
		t.Fatal("expected error for not found lease")
	}
}

func TestLookupLease_NonOKStatus(t *testing.T) {
	srv := newLeaseMockServer(t, "", 0, "", http.StatusInternalServerError)
	defer srv.Close()

	c := clientForTest(t, srv.URL)
	_, err := c.LookupLease(context.Background(), "lease/abc")
	if err == nil {
		t.Fatal("expected error for non-OK status")
	}
}
