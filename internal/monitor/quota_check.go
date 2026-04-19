package monitor

import (
	"context"
	"fmt"

	"github.com/danhale-git/vaultpulse/internal/alert"
	"github.com/danhale-git/vaultpulse/internal/vault"
)

// QuotaChecker alerts when no quota rules are configured in Vault.
type QuotaChecker struct {
	client *vault.Client
	notifier alert.Notifier
}

// NewQuotaChecker creates a QuotaChecker.
func NewQuotaChecker(c *vault.Client, n alert.Notifier) *QuotaChecker {
	return &QuotaChecker{client: c, notifier: n}
}

// Check lists quota rules and fires a warning alert if none are defined.
func (q *QuotaChecker) Check(ctx context.Context) error {
	keys, err := q.client.ListQuotas()
	if err != nil {
		return fmt.Errorf("quota check: %w", err)
	}

	if len(keys) == 0 {
		a := alert.NewAlert(
			"No Vault quota rules configured",
			"sys/quotas/rate-limit",
			alert.SeverityWarning,
		)
		if err := q.notifier.Send(ctx, a); err != nil {
			return fmt.Errorf("quota check notify: %w", err)
		}
	}
	return nil
}
