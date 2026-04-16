package monitor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yourusername/vaultpulse/internal/alert"
	"github.com/yourusername/vaultpulse/internal/vault"
)

func newPolicyCheckServer(emptyPolicy bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/sys/policies/acl" && r.URL.RawQuery == "list=true":
			json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{"keys": []string{"mypolicy"}},
			})
		case r.URL.Path == "/v1/sys/policies/acl/mypolicy":
			rules := "path \"secret/*\" { capabilities = [\"read\"] }"
			if emptyPolicy {
				rules = ""
			}
			json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{"policy": rules},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestPolicyChecker_NoAlertWhenRulesPresent(t *testing.T) {
	srv := newPolicyCheckServer(false)
	defer srv.Close()
	c := &vault.Client{}
	*c = vault.Client{}
	client, _ := vault.NewClient(testConfig(srv.URL))
	var fired []alert.Alert
	notifier := &captureNotifier{alerts: &fired}
	checker := NewPolicyChecker(client, []alert.Notifier{notifier})
	if err := checker.Check(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fired) != 0 {
		t.Errorf("expected no alerts, got %d", len(fired))
	}
}

func TestPolicyChecker_AlertWhenEmptyRules(t *testing.T) {
	srv := newPolicyCheckServer(true)
	defer srv.Close()
	client, _ := vault.NewClient(testConfig(srv.URL))
	var fired []alert.Alert
	notifier := &captureNotifier{alerts: &fired}
	checker := NewPolicyChecker(client, []alert.Notifier{notifier})
	if err := checker.Check(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fired) != 1 {
		t.Errorf("expected 1 alert, got %d", len(fired))
	}
}
