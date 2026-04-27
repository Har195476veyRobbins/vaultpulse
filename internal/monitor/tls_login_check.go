package monitor

import (
	"context"
	"fmt"

	"github.com/yourusername/vaultpulse/internal/alert"
	"github.com/yourusername/vaultpulse/internal/vault"
)

// TLSLoginChecker verifies that a TLS certificate login succeeds and that the
// resulting token has an acceptable TTL.
type TLSLoginChecker struct {
	client    *vault.Client
	notifiers []alert.Notifier
	req       vault.TLSLoginRequest
	warnTTL   int
}

// NewTLSLoginChecker creates a TLSLoginChecker.
func NewTLSLoginChecker(client *vault.Client, req vault.TLSLoginRequest, warnTTL int, notifiers []alert.Notifier) *TLSLoginChecker {
	return &TLSLoginChecker{
		client:    client,
		notifiers: notifiers,
		req:       req,
		warnTTL:   warnTTL,
	}
}

// Check performs the TLS login and fires alerts based on the result.
func (c *TLSLoginChecker) Check(ctx context.Context) error {
	resp, err := c.client.LoginWithTLS(ctx, c.req)
	if err != nil {
		a := alert.NewAlert(
			"TLS Login Failed",
			fmt.Sprintf("TLS certificate login (mount=%s) failed: %v", c.req.Mount, err),
			alert.SeverityCritical,
		)
		for _, n := range c.notifiers {
			_ = n.Send(ctx, a)
		}
		return err
	}

	if resp.LeaseDuration > 0 && resp.LeaseDuration <= c.warnTTL {
		a := alert.NewAlert(
			"TLS Login Token Expiring Soon",
			fmt.Sprintf("TLS login token (mount=%s) expires in %ds", c.req.Mount, resp.LeaseDuration),
			alert.SeverityWarning,
		)
		for _, n := range c.notifiers {
			_ = n.Send(ctx, a)
		}
	}

	return nil
}
