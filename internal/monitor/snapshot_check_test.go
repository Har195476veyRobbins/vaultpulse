package monitor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yourusername/vaultpulse/internal/alert"
	"github.com/yourusername/vaultpulse/internal/audit"
	"github.com/yourusername/vaultpulse/internal/vault"
)

func newSnapshotCheckServer(t *testing.T, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		if status == http.StatusOK {
			_, _ = w.Write([]byte("data"))
		}
	}))
}

type captureNotifier struct {
	called bool
	last   *alert.Alert
}

func (c *captureNotifier) Send(_ context.Context, a *alert.Alert) error {
	c.called = true
	c.last = a
	return nil
}

func TestSnapshotChecker_OK(t *testing.T) {
	srv := newSnapshotCheckServer(t, http.StatusOK)
	defer srv.Close()

	client, _ := vault.NewClient(testConfig(srv.URL))
	n := &captureNotifier{}
	checker := NewSnapshotChecker(client, n, audit.NewNoop())

	if err := checker.Check(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n.called {
		t.Error("expected no alert for successful snapshot")
	}
}

func TestSnapshotChecker_NotAvailable(t *testing.T) {
	srv := newSnapshotCheckServer(t, http.StatusNotFound)
	defer srv.Close()

	client, _ := vault.NewClient(testConfig(srv.URL))
	n := &captureNotifier{}
	checker := NewSnapshotChecker(client, n, audit.NewNoop())

	if err := checker.Check(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !n.called {
		t.Error("expected alert when snapshot not available")
	}
	if n.last.Severity != alert.SeverityWarning {
		t.Errorf("expected warning severity, got %s", n.last.Severity)
	}
}

func TestSnapshotChecker_Error(t *testing.T) {
	srv := newSnapshotCheckServer(t, http.StatusInternalServerError)
	defer srv.Close()

	client, _ := vault.NewClient(testConfig(srv.URL))
	n := &captureNotifier{}
	checker := NewSnapshotChecker(client, n, audit.NewNoop())

	_ = checker.Check(context.Background())
	if !n.called {
		t.Error("expected alert on snapshot error")
	}
	if n.last.Severity != alert.SeverityCritical {
		t.Errorf("expected critical severity, got %s", n.last.Severity)
	}
}
