package monitor

import (
	"fmt"
	"time"

	"github.com/subtlepseudonym/vaultpulse/internal/alert"
	"github.com/subtlepseudonym/vaultpulse/internal/vault"
)

// TokenLoginChecker validates the active Vault token and alerts if it is
// expiring soon or has insufficient TTL.
type TokenLoginChecker struct {
	client    *vault.Client
	token     string
	warnTTL   time.Duration
	notifiers []alert.Notifier
}

// NewTokenLoginChecker creates a new TokenLoginChecker.
func NewTokenLoginChecker(client *vault.Client, token string, warnTTL time.Duration, notifiers []alert.Notifier) *TokenLoginChecker {
	return &TokenLoginChecker{
		client:    client,
		token:     token,
		warnTTL:   warnTTL,
		notifiers: notifiers,
	}
}

// Check performs the token login validation and fires alerts as needed.
func (c *TokenLoginChecker) Check() error {
	res, err := c.client.LoginWithToken(c.token)
	if err != nil {
		return fmt.Errorf("token login check: %w", err)
	}

	var sev alert.Severity
	var msg string

	switch {
	case res.TTL == 0:
		sev = alert.SeverityCritical
		msg = "Vault token has no TTL (non-renewable root or expired)"
	case res.TTL < c.warnTTL:
		sev = alert.SeverityWarning
		msg = fmt.Sprintf("Vault token expiring soon: TTL=%s policies=%v", res.TTL, res.Policies)
	default:
		return nil
	}

	a := alert.NewAlert("vault/token/login", msg, sev)
	for _, n := range c.notifiers {
		if err := n.Send(a); err != nil {
			return fmt.Errorf("send alert: %w", err)
		}
	}
	return nil
}
