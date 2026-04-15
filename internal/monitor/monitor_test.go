package monitor_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yourusername/vaultpulse/internal/alert"
	"github.com/yourusername/vaultpulse/internal/config"
	"github.com/yourusername/vaultpulse/internal/monitor"
	"github.com/yourusername/vaultpulse/internal/vault"
)

// fakeNotifier records how many times Send was called.
type fakeNotifier struct {
	calls atomic.Int32
}

func (f *fakeNotifier) Send(_ context.Context, _ alert.Alert) error {
	f.calls.Add(1)
	return nil
}

func newTestVaultServer(ttl string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{"metadata":{"deletion_time":"` + ttl + `"}}}`))
	}))
}

func TestMonitor_CheckSecrets_AlertsFired(t *testing.T) {
	// Use a TTL that is expiring soon (within 24h).
	soon := time.Now().Add(1 * time.Hour).UTC().Format(time.RFC3339)
	srv := newTestVaultServer(soon)
	defer srv.Close()

	cfg := &config.Config{
		Address:       srv.URL,
		Token:         "test-token",
		SecretPaths:   []string{"secret/data/myapp/db"},
		WarnThreshold: 24 * time.Hour,
		CheckInterval: 100 * time.Millisecond,
	}

	client, err := vault.NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	notifier := &fakeNotifier{}
	m := monitor.New(client, []alert.Notifier{notifier}, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	_ = m.Run(ctx)

	if notifier.calls.Load() == 0 {
		t.Error("expected at least one alert to be sent, got none")
	}
}

func TestMonitor_CheckSecrets_NoAlertWhenNotExpiring(t *testing.T) {
	// TTL far in the future — should not trigger alerts.
	far := time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339)
	srv := newTestVaultServer(far)
	defer srv.Close()

	cfg := &config.Config{
		Address:       srv.URL,
		Token:         "test-token",
		SecretPaths:   []string{"secret/data/myapp/db"},
		WarnThreshold: 24 * time.Hour,
		CheckInterval: 100 * time.Millisecond,
	}

	client, err := vault.NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	notifier := &fakeNotifier{}
	m := monitor.New(client, []alert.Notifier{notifier}, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	_ = m.Run(ctx)

	if notifier.calls.Load() != 0 {
		t.Errorf("expected no alerts, got %d", notifier.calls.Load())
	}
}
