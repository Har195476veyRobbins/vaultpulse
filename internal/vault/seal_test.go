package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newSealMockServer(t *testing.T, status int, body interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if body != nil {
			_ = json.NewEncoder(w).Encode(body)
		}
	}))
}

func TestGetSealStatus_Unsealed(t *testing.T) {
	payload := SealStatus{Sealed: false, Initialized: true, Version: "1.15.0", ClusterName: "vault-cluster"}
	srv := newSealMockServer(t, http.StatusOK, payload)
	defer srv.Close()

	client := &Client{address: srv.URL, token: "test-token", http: srv.Client()}
	status, err := client.GetSealStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.Sealed {
		t.Error("expected unsealed")
	}
	if status.ClusterName != "vault-cluster" {
		t.Errorf("expected cluster name vault-cluster, got %s", status.ClusterName)
	}
}

func TestGetSealStatus_Sealed(t *testing.T) {
	payload := SealStatus{Sealed: true, Initialized: true, Progress: 1, T: 3, N: 5}
	srv := newSealMockServer(t, http.StatusOK, payload)
	defer srv.Close()

	client := &Client{address: srv.URL, token: "test-token", http: srv.Client()}
	status, err := client.GetSealStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !status.Sealed {
		t.Error("expected sealed")
	}
}

func TestGetSealStatus_NonOKStatus(t *testing.T) {
	srv := newSealMockServer(t, http.StatusInternalServerError, nil)
	defer srv.Close()

	client := &Client{address: srv.URL, token: "test-token", http: srv.Client()}
	_, err := client.GetSealStatus()
	if err == nil {
		t.Fatal("expected error for non-OK status")
	}
}

func TestGetSealStatus_BadURL(t *testing.T) {
	client := &Client{address: "http://127.0.0.1:0", token: "tok", http: &http.Client{}}
	_, err := client.GetSealStatus()
	if err == nil {
		t.Fatal("expected error for bad URL")
	}
}
