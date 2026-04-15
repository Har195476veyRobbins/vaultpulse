package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newMetadataMockServer(t *testing.T, status int, payload interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if payload != nil {
			_ = json.NewEncoder(w).Encode(payload)
		}
	}))
}

func TestGetKVMetadata_Success(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	payload := map[string]interface{}{
		"data": map[string]interface{}{
			"current_version": 3,
			"oldest_version":  1,
			"max_versions":    10,
			"created_time":    now.Add(-48 * time.Hour).Format(time.RFC3339Nano),
			"updated_time":    now.Format(time.RFC3339Nano),
			"versions": map[string]interface{}{
				"3": map[string]interface{}{
					"deletion_time": now.Add(24 * time.Hour).Format(time.RFC3339Nano),
					"destroyed":     false,
				},
			},
		},
	}

	srv := newMetadataMockServer(t, http.StatusOK, payload)
	defer srv.Close()

	client := &Client{address: srv.URL, token: "test-token", http: srv.Client()}
	meta, err := client.GetKVMetadata("secret", "myapp/db")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if meta.CurrentVersion != 3 {
		t.Errorf("expected current version 3, got %d", meta.CurrentVersion)
	}
	if meta.MaxVersions != 10 {
		t.Errorf("expected max versions 10, got %d", meta.MaxVersions)
	}
	if meta.DeletedAt == nil {
		t.Fatal("expected DeletedAt to be set")
	}
	if meta.DeletedAt.Before(now) {
		t.Errorf("expected DeletedAt in the future")
	}
}

func TestGetKVMetadata_NotFound(t *testing.T) {
	srv := newMetadataMockServer(t, http.StatusNotFound, nil)
	defer srv.Close()

	client := &Client{address: srv.URL, token: "test-token", http: srv.Client()}
	_, err := client.GetKVMetadata("secret", "missing/path")
	if err == nil {
		t.Fatal("expected error for 404, got nil")
	}
}

func TestGetKVMetadata_UnexpectedStatus(t *testing.T) {
	srv := newMetadataMockServer(t, http.StatusInternalServerError, nil)
	defer srv.Close()

	client := &Client{address: srv.URL, token: "test-token", http: srv.Client()}
	_, err := client.GetKVMetadata("secret", "some/path")
	if err == nil {
		t.Fatal("expected error for 500, got nil")
	}
}

func TestGetKVMetadata_NoDeletionTime(t *testing.T) {
	payload := map[string]interface{}{
		"data": map[string]interface{}{
			"current_version": 1,
			"oldest_version":  1,
			"max_versions":    0,
			"created_time":    time.Now().UTC().Format(time.RFC3339Nano),
			"updated_time":    time.Now().UTC().Format(time.RFC3339Nano),
			"versions": map[string]interface{}{
				"1": map[string]interface{}{
					"deletion_time": "",
					"destroyed":     false,
				},
			},
		},
	}

	srv := newMetadataMockServer(t, http.StatusOK, payload)
	defer srv.Close()

	client := &Client{address: srv.URL, token: "test-token", http: srv.Client()}
	meta, err := client.GetKVMetadata("secret", "no/expiry")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if meta.DeletedAt != nil {
		t.Errorf("expected DeletedAt to be nil when no deletion_time set")
	}
}
