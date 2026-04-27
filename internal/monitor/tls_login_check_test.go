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

func newTLSLoginCheckServer(t *testing.T, leaseDuration int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"auth": map[string]interface{}{
				"client_token":   "tok",
				"lease_duration": leaseDuration,
				"renewable":      true,
			},
		})
	}))
}

func newTLSMonitor(t *testing.T, addr string, leaseDuration int, notifiers []alert.Notifier) *TLSLoginChecker {
	t.Helper()
	c, err := vault.NewClient(vault.ClientConfig{Address: addr, Token: "t"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	req := vault.TLSLoginRequest{
		Mount:   "cert",
		CertPEM: []byte("dummy"),
		KeyPEM:  []byte("dummy"),
	}
	return NewTLSLoginChecker(c, req, 300, notifiers)
}

func TestTLSLoginChecker_NoAlertWhenHealthy(t *testing.T) {
	srv := newTLSLoginCheckServer(t, 3600)
	defer srv.Close()

	fired := false
	n := &fakeNotifier{fn: func(a alert.Alert) { fired = true }}
	checker := newTLSMonitor(t, srv.URL, 3600, []alert.Notifier{n})
	_ = checker.Check(context.Background())
	if fired {
		t.Error("expected no alert for healthy TLS login")
	}
}

func TestTLSLoginChecker_AlertWhenExpiringSoon(t *testing.T) {
	srv := newTLSLoginCheckServer(t, 60)
	defer srv.Close()

	fired := false
	n := &fakeNotifier{fn: func(a alert.Alert) { fired = true }}
	checker := newTLSMonitor(t, srv.URL, 60, []alert.Notifier{n})
	_ = checker.Check(context.Background())
	if !fired {
		t.Error("expected warning alert for expiring TLS token")
	}
}

func TestTLSLoginChecker_CriticalOnLoginFailure(t *testing.T) {
	fired := false
	var gotSeverity alert.Severity
	n := &fakeNotifier{fn: func(a alert.Alert) {
		fired = true
		gotSeverity = a.Severity
	}}
	checker := newTLSMonitor(t, "http://127.0.0.1:0", 3600, []alert.Notifier{n})
	_ = checker.Check(context.Background())
	if !fired {
		t.Error("expected critical alert on login failure")
	}
	if gotSeverity != alert.SeverityCritical {
		t.Errorf("expected critical severity, got %v", gotSeverity)
	}
}
