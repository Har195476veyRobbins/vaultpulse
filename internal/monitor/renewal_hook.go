package monitor

import (
	"context"
	"log"
	"time"

	"github.com/yourusername/vaultpulse/internal/vault"
)

// Renewer is satisfied by any type that can renew a Vault lease.
type Renewer interface {
	RenewLease(ctx context.Context, path string, increment time.Duration) vault.RenewalResult
}

// RenewalHook wraps a Monitor and automatically renews leases for secrets
// that are expiring soon, before alerts are dispatched.
type RenewalHook struct {
	monitor   *Monitor
	renewer   Renewer
	increment time.Duration
}

// NewRenewalHook creates a RenewalHook that will attempt to renew leases
// for expiring secrets using the provided Renewer.
func NewRenewalHook(m *Monitor, r Renewer, increment time.Duration) *RenewalHook {
	if increment <= 0 {
		increment = time.Hour
	}
	return &RenewalHook{monitor: m, renewer: r, increment: increment}
}

// CheckAndRenew runs the monitor's secret check, attempts renewal for any
// expiring secrets, and returns the updated list of secrets.
func (rh *RenewalHook) CheckAndRenew(ctx context.Context) []vault.SecretMeta {
	secrets := rh.monitor.CheckSecrets(ctx)

	for i, s := range secrets {
		if !s.Expiring {
			continue
		}
		result := rh.renewer.RenewLease(ctx, s.Path, rh.increment)
		if result.Err != nil {
			log.Printf("[renewal] failed to renew %s: %v", s.Path, result.Err)
			continue
		}
		log.Printf("[renewal] renewed %s, new TTL: %v", s.Path, result.NewTTL)
		// Update the in-memory record to reflect the renewed TTL.
		secrets[i].TTL = result.NewTTL
		secrets[i].Expiring = false
	}

	return secrets
}
