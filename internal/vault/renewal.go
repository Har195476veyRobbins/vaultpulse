package vault

import (
	"context"
	"fmt"
	"time"
)

// RenewalResult holds the outcome of a lease renewal attempt.
type RenewalResult struct {
	Path      string
	Renewed   bool
	NewTTL    time.Duration
	RenewedAt time.Time
	Err       error
}

// RenewLease attempts to renew a Vault lease for the given secret path.
// It uses the secret's lease ID retrieved from metadata.
func (c *Client) RenewLease(ctx context.Context, path string, increment time.Duration) RenewalResult {
	result := RenewalResult{
		Path:      path,
		RenewedAt: time.Now(),
	}

	meta, err := c.GetSecretMeta(ctx, path)
	if err != nil {
		result.Err = fmt.Errorf("fetch meta for %s: %w", path, err)
		return result
	}

	if meta.LeaseID == "" {
		result.Err = fmt.Errorf("secret %s has no renewable lease", path)
		return result
	}

	incSeconds := int(increment.Seconds())
	rawSecret, err := c.logical.Write("sys/leases/renew", map[string]interface{}{
		"lease_id":  meta.LeaseID,
		"increment": incSeconds,
	})
	if err != nil {
		result.Err = fmt.Errorf("renew lease %s: %w", meta.LeaseID, err)
		return result
	}

	if rawSecret == nil {
		result.Err = fmt.Errorf("empty response renewing lease for %s", path)
		return result
	}

	result.Renewed = true
	result.NewTTL = time.Duration(rawSecret.LeaseDuration) * time.Second
	return result
}
