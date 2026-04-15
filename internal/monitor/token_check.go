package monitor

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/yourusername/vaultpulse/internal/alert"
)

// TokenChecker checks the Vault token's TTL and fires alerts when it is
// expiring soon. It is intended to be called alongside CheckSecrets.
type TokenChecker struct {
	monitor         *Monitor
	warnThreshold   time.Duration
	criticalThreshold time.Duration
}

// NewTokenChecker creates a TokenChecker with the given thresholds.
// If zero values are passed, sensible defaults are applied.
func NewTokenChecker(m *Monitor, warn, critical time.Duration) *TokenChecker {
	if warn == 0 {
		warn = 24 * time.Hour
	}
	if critical == 0 {
		critical = 4 * time.Hour
	}
	return &TokenChecker{
		monitor:           m,
		warnThreshold:     warn,
		criticalThreshold: critical,
	}
}

// Check looks up the current token and sends an alert if the TTL is below
// either threshold. Returns an error only when the lookup itself fails.
func (tc *TokenChecker) Check(ctx context.Context) error {
	info, err := tc.monitor.vault.LookupSelfToken(ctx)
	if err != nil {
		return fmt.Errorf("token check: %w", err)
	}

	if info.TTL <= 0 {
		// Root or non-expiring token — nothing to alert on.
		return nil
	}

	var severity string
	switch {
	case info.TTL <= tc.criticalThreshold:
		severity = alert.SeverityCritical
	case info.TTL <= tc.warnThreshold:
		severity = alert.SeverityWarning
	default:
		return nil
	}

	a := alert.NewAlert(
		fmt.Sprintf("Vault token '%s' expires in %s", info.DisplayName, info.TTL.Round(time.Minute)),
		severity,
	)

	for _, n := range tc.monitor.notifiers {
		if err := n.Send(ctx, a); err != nil {
			log.Printf("token check: notifier error: %v", err)
		}
	}
	return nil
}
