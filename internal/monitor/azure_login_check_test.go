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

func newAzureLoginServer(t *testing.T, statusCode int, leaseDuration int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(statusCode)
		if statusCode == http.StatusOK {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token":   "tok-azure",
					"lease_duration": leaseDuration,
					"renewable":      true,
				},
			})
		}
	}))
}

func newAzureMonitor(t *testing.T, url string, notifier alert.Notifier) *AzureLoginChecker {
	t.Helper()
	client, err := vault.NewClient(vault.Config{Address: url, Token: "root"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return NewAzureLoginChecker(client, AzureLoginConfig{
		Role:              "my-role",
		JWT:               "eyJ...",
		SubscriptionID:    "sub-123",
		ResourceGroupName: "rg-prod",
	}, notifier)
}

func TestAzureLoginChecker_NoAlertWhenHealthy(t *testing.T) {
	srv := newAzureLoginServer(t, http.StatusOK, 7200)
	defer srv.Close()

	var captured []alert.Alert
	notifier := &captureNotifier{alerts: &captured}
	checker := newAzureMonitor(t, srv.URL, notifier)

	if err := checker.Check(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(captured) != 0 {
		t.Errorf("expected no alerts, got %d", len(captured))
	}
}

func TestAzureLoginChecker_AlertWhenExpiringSoon(t *testing.T) {
	srv := newAzureLoginServer(t, http.StatusOK, 1800) // below 3600 threshold
	defer srv.Close()

	var captured []alert.Alert
	notifier := &captureNotifier{alerts: &captured}
	checker := newAzureMonitor(t, srv.URL, notifier)

	if err := checker.Check(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(captured) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(captured))
	}
	if captured[0].Severity != alert.SeverityWarning {
		t.Errorf("expected warning severity, got %v", captured[0].Severity)
	}
}

func TestAzureLoginChecker_CriticalOnLoginFailure(t *testing.T) {
	srv := newAzureLoginServer(t, http.StatusForbidden, 0)
	defer srv.Close()

	var captured []alert.Alert
	notifier := &captureNotifier{alerts: &captured}
	checker := newAzureMonitor(t, srv.URL, notifier)

	if err := checker.Check(context.Background()); err == nil {
		t.Fatal("expected error on login failure")
	}
	if len(captured) != 1 {
		t.Fatalf("expected 1 critical alert, got %d", len(captured))
	}
	if captured[0].Severity != alert.SeverityCritical {
		t.Errorf("expected critical severity, got %v", captured[0].Severity)
	}
}
