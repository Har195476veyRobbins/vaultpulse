package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newSysInfoMockServer(t *testing.T, status int, payload interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sys/host-info" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
		if payload != nil {
			_ = json.NewEncoder(w).Encode(payload)
		}
	}))
}

func TestGetSysInfo_Success(t *testing.T) {
	payload := map[string]interface{}{
		"data": map[string]interface{}{
			"cpu_count":  4,
			"hostname":   "vault-node-1",
			"os":         "linux",
			"os_version": "5.15.0",
			"uptime":     uint64(86400),
		},
	}
	srv := newSysInfoMockServer(t, http.StatusOK, payload)
	defer srv.Close()

	client := newTestVaultClient(t, srv.URL)
	info, err := client.GetSysInfo()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Hostname != "vault-node-1" {
		t.Errorf("expected hostname vault-node-1, got %s", info.Hostname)
	}
	if info.CPUCount != 4 {
		t.Errorf("expected cpu_count 4, got %d", info.CPUCount)
	}
	if info.OS != "linux" {
		t.Errorf("expected os linux, got %s", info.OS)
	}
}

func TestGetSysInfo_NonOKStatus(t *testing.T) {
	srv := newSysInfoMockServer(t, http.StatusForbidden, nil)
	defer srv.Close()

	client := newTestVaultClient(t, srv.URL)
	_, err := client.GetSysInfo()
	if err == nil {
		t.Fatal("expected error for non-OK status, got nil")
	}
}

func TestGetSysInfo_BadURL(t *testing.T) {
	client := newTestVaultClient(t, "http://127.0.0.1:0")
	_, err := client.GetSysInfo()
	if err == nil {
		t.Fatal("expected error for bad URL, got nil")
	}
}
