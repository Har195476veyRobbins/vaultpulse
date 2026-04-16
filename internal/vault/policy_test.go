package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newPolicyMockServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/sys/policies/acl" && r.URL.RawQuery == "list=true":
			json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{"keys": []string{"default", "admin"}},
			})
		case r.URL.Path == "/v1/sys/policies/acl/admin":
			json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{"policy": "path \"secret/*\" { capabilities = [\"read\"] }"},
			})
		case r.URL.Path == "/v1/sys/policies/acl/missing":
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
}

func TestListPolicies_Success(t *testing.T) {
	srv := newPolicyMockServer(t)
	defer srv.Close()
	c := &Client{address: srv.URL, token: "tok", http: srv.Client()}
	policies, err := c.ListPolicies(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(policies) != 2 {
		t.Fatalf("expected 2 policies, got %d", len(policies))
	}
}

func TestGetPolicy_Success(t *testing.T) {
	srv := newPolicyMockServer(t)
	defer srv.Close()
	c := &Client{address: srv.URL, token: "tok", http: srv.Client()}
	info, err := c.GetPolicy(context.Background(), "admin")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Name != "admin" {
		t.Errorf("expected name admin, got %s", info.Name)
	}
	if info.Rules == "" {
		t.Error("expected non-empty rules")
	}
}

func TestGetPolicy_NotFound(t *testing.T) {
	srv := newPolicyMockServer(t)
	defer srv.Close()
	c := &Client{address: srv.URL, token: "tok", http: srv.Client()}
	_, err := c.GetPolicy(context.Background(), "missing")
	if err == nil {
		t.Fatal("expected error for missing policy")
	}
}

func TestListPolicies_BadURL(t *testing.T) {
	c := &Client{address: "http://127.0.0.1:0", token: "tok", http: &http.Client{}}
	_, err := c.ListPolicies(context.Background())
	if err == nil {
		t.Fatal("expected error for bad URL")
	}
}
