package monitor

import (
	"context"
	"fmt"
	"time"

	"github.com/your-org/vaultpulse/internal/alert"
	"github.com/your-org/vaultpulse/internal/vault"
)

// LeaseChecker monitors specific Vault lease IDs for expiry.
type LeaseChecker struct {
	client   *vault.Client
	leaseIDs []string
	warning  time.Duration
	critical time.Duration
	notifier alert.Notifier
}

// NewLeaseChecker creates a LeaseChecker for the provided lease IDs.
func NewLeaseChecker(client *vault.Client, leaseIDs []string, warning, critical time.Duration, n alert.Notifier) *LeaseChecker {
	return &LeaseChecker{
		client:   client,
		leaseIDs: leaseIDs,
		warning:  warning,
		critical: critical,
		notifier: n,
	}
}

// Check evaluates all tracked leases and fires alerts as needed.
func (lc *LeaseChecker) Check(ctx context.Context) error {
	for _, id := range lc.leaseIDs {
		info, err := lc.client.LookupLease(ctx, id)
		if err != nil {
			return fmt.Errorf("lease lookup failed for %s: %w", id, err)
		}

		ttl := time.Until(info.ExpireTime)
		var sev alert.Severity

		switch {
		case ttl <= 0:
			sev = alert.SeverityCritical
		case ttl <= lc.critical:
			sev = alert.SeverityCritical
		case ttl <= lc.warning:
			sev = alert.SeverityWarning
		default:
			continue
		}

		a := alert.NewAlert(
			fmt.Sprintf("Vault lease expiring: %s", id),
			fmt.Sprintf("Lease %s expires in %s", id, ttl.Round(time.Second)),
			sev,
		)
		if err := lc.notifier.Send(ctx, a); err != nil {
			return fmt.Errorf("failed to send alert for lease %s: %w", id, err)
		}
	}
	return nil
}
