package monitor

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/subtlepseudonym/vaultpulse/internal/alert"
	"github.com/subtlepseudonym/vaultpulse/internal/vault"
)

func newTokenLoginServer(t *testing.T, ttl int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"id":        "s.test",
				"policies":  []string{"default"},
				"ttl":       ttl,
				"renewable": true,
			},
		})
	}))
}

type captureNotifier struct {
	alerts []alert.Alert
}

func (c *captureNotifier) Send(a alert.Alert) error {
	c.alerts = append(c.alerts, a)
	return nil
}

func TestTokenLoginChecker_NoAlertWhenHealthy(t *testing.T) {
	srv := newTokenLoginServer(t, 7200)
	defer srv.Close()

	client, _ := vault.NewClient(srv.URL, "s.test")
	n := &captureNotifier{}
	checker := NewTokenLoginChecker(client, "s.test", 30*time.Minute, []alert.Notifier{n})

	if err := checker.Check(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(n.alerts) != 0 {
		t.Errorf("expected no alerts, got %d", len(n.alerts))
	}
}

func TestTokenLoginChecker_AlertWhenExpiringSoon(t *testing.T) {
	srv := newTokenLoginServer(t, 300) // 5 minutes
	defer srv.Close()

	client, _ := vault.NewClient(srv.URL, "s.test")
	n := &captureNotifier{}
	checker := NewTokenLoginChecker(client, "s.test", 30*time.Minute, []alert.Notifier{n})

	if err := checker.Check(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(n.alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(n.alerts))
	}
	if n.alerts[0].Severity != alert.SeverityWarning {
		t.Errorf("expected warning severity, got %s", n.alerts[0].Severity)
	}
}

func TestTokenLoginChecker_CriticalWhenNoTTL(t *testing.T) {
	srv := newTokenLoginServer(t, 0)
	defer srv.Close()

	client, _ := vault.NewClient(srv.URL, "s.test")
	n := &captureNotifier{}
	checker := NewTokenLoginChecker(client, "s.test", 30*time.Minute, []alert.Notifier{n})

	if err := checker.Check(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(n.alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(n.alerts))
	}
	if n.alerts[0].Severity != alert.SeverityCritical {
		t.Errorf("expected critical severity, got %s", n.alerts[0].Severity)
	}
}
