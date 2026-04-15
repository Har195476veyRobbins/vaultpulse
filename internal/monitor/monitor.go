package monitor

import (
	"fmt"
	"log"
	"time"

	"github.com/yourusername/vaultpulse/internal/alert"
	"github.com/yourusername/vaultpulse/internal/config"
	"github.com/yourusername/vaultpulse/internal/vault"
)

// Monitor periodically checks Vault secrets and fires alerts.
type Monitor struct {
	vault     *vault.Client
	notifiers []alert.Notifier
	onAlert   func(alert.Alert)
	warnTTL   time.Duration
}

// New creates a Monitor from the given config and notifiers.
func New(cfg *config.Config, notifiers []alert.Notifier) (*Monitor, error) {
	client, err := vault.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("creating vault client: %w", err)
	}
	m := &Monitor{
		vault:     client,
		notifiers: notifiers,
		warnTTL:   time.Duration(cfg.WarnTTLDays) * 24 * time.Hour,
	}
	m.onAlert = m.dispatchAlert
	return m, nil
}

// CheckSecrets fetches all configured secret paths and fires alerts for
// secrets that are expiring soon or already expired.
func (m *Monitor) CheckSecrets(paths []string) error {
	var firstErr error
	for _, p := range paths {
		meta, err := m.vault.GetSecretMeta(p)
		if err != nil {
			log.Printf("[monitor] error checking %s: %v", p, err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}

		if meta.TTL <= 0 {
			continue
		}

		if vault.IsExpiringSoon(meta, m.warnTTL) {
			severity := alert.SeverityWarning
			if meta.TTL < 0 {
				severity = alert.SeverityCritical
			}
			a := alert.NewAlert(
				fmt.Sprintf("secret %s expires in %s", p, (time.Duration(meta.TTL)*time.Second).Round(time.Second)),
				severity,
			)
			m.fireAlert(a)
		}
	}
	return firstErr
}

// fireAlert invokes the configured onAlert handler (testable hook).
func (m *Monitor) fireAlert(a alert.Alert) {
	m.onAlert(a)
}

// dispatchAlert sends an alert to all registered notifiers.
func (m *Monitor) dispatchAlert(a alert.Alert) {
	for _, n := range m.notifiers {
		if err := n.Send(a); err != nil {
			log.Printf("[monitor] notifier error: %v", err)
		}
	}
}

// testConfig returns a minimal config pointing at the given Vault URL.
func testConfig(t interface{ Helper(); Fatal(...interface{}) }, addr string) *config.Config {
	t.Helper()
	return &config.Config{
		Vault: config.VaultConfig{Address: addr, Token: "test-token"},
		WarnTTLDays: 7,
	}
}
