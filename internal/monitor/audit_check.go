package monitor

import (
	"fmt"

	"vaultpulse/internal/alert"
	"vaultpulse/internal/vault"
)

// AuditChecker warns when no audit backends are enabled in Vault.
type AuditChecker struct {
	client *vault.Client
	notifiers []alert.Notifier
}

// NewAuditChecker creates an AuditChecker.
func NewAuditChecker(client *vault.Client, notifiers []alert.Notifier) *AuditChecker {
	return &AuditChecker{client: client, notifiers: notifiers}
}

// Check fetches audit backends and fires a critical alert if none are enabled.
func (a *AuditChecker) Check() error {
	backends, err := a.client.ListAuditBackends()
	if err != nil {
		return fmt.Errorf("audit check: %w", err)
	}

	if len(backends) == 0 {
		notif := alert.NewAlert(
			"No audit backends enabled",
			"Vault has no audit devices configured. All requests are unaudited.",
			alert.SeverityCritical,
		)
		for _, n := range a.notifiers {
			if err := n.Send(notif); err != nil {
				return fmt.Errorf("audit check: notify: %w", err)
			}
		}
	}
	return nil
}
