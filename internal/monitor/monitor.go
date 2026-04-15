package monitor

import (
	"context"
	"log"
	"time"

	"github.com/yourusername/vaultpulse/internal/alert"
	"github.com/yourusername/vaultpulse/internal/config"
	"github.com/yourusername/vaultpulse/internal/vault"
)

// Monitor periodically checks Vault secrets and sends alerts for expiring ones.
type Monitor struct {
	client    *vault.Client
	notifiers []alert.Notifier
	cfg       *config.Config
}

// New creates a new Monitor with the given Vault client, notifiers, and config.
func New(client *vault.Client, notifiers []alert.Notifier, cfg *config.Config) *Monitor {
	return &Monitor{
		client:    client,
		notifiers: notifiers,
		cfg:       cfg,
	}
}

// Run starts the monitoring loop, checking secrets at the configured interval.
// It blocks until the context is cancelled.
func (m *Monitor) Run(ctx context.Context) error {
	ticker := time.NewTicker(m.cfg.CheckInterval)
	defer ticker.Stop()

	log.Printf("monitor: starting, check interval=%s", m.cfg.CheckInterval)

	// Run once immediately before waiting for the first tick.
	m.checkSecrets(ctx)

	for {
		select {
		case <-ticker.C:
			m.checkSecrets(ctx)
		case <-ctx.Done():
			log.Println("monitor: shutting down")
			return ctx.Err()
		}
	}
}

// checkSecrets iterates over configured secret paths, retrieves metadata,
// and fires alerts for any secrets that are expiring soon.
func (m *Monitor) checkSecrets(ctx context.Context) {
	for _, path := range m.cfg.SecretPaths {
		meta, err := m.client.GetSecretMeta(ctx, path)
		if err != nil {
			log.Printf("monitor: failed to get secret meta for %q: %v", path, err)
			continue
		}

		if !m.client.IsExpiringSoon(meta, m.cfg.WarnThreshold) {
			continue
		}

		a := alert.NewAlert(path, meta.TTL, m.cfg.WarnThreshold)
		for _, n := range m.notifiers {
			if err := n.Send(ctx, a); err != nil {
				log.Printf("monitor: notifier failed for %q: %v", path, err)
			}
		}
	}
}
