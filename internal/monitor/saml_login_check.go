package monitor

import (
	"fmt"
	"time"

	"github.com/yourusername/vaultpulse/internal/alert"
	"github.com/yourusername/vaultpulse/internal/vault"
)

// SAMLLoginChecker validates that SAML authentication succeeds and the returned
// token has an acceptable TTL.
type SAMLLoginChecker struct {
	client       *vault.Client
	notifier     alert.Notifier
	roleName     string
	samlResponse string
	mount        string
	warnTTL      time.Duration
}

// NewSAMLLoginChecker creates a SAMLLoginChecker.
func NewSAMLLoginChecker(
	client *vault.Client,
	notifier alert.Notifier,
	roleName, samlResponse, mount string,
	warnTTL time.Duration,
) *SAMLLoginChecker {
	if mount == "" {
		mount = "saml"
	}
	return &SAMLLoginChecker{
		client:       client,
		notifier:     notifier,
		roleName:     roleName,
		samlResponse: samlResponse,
		mount:        mount,
		warnTTL:      warnTTL,
	}
}

// Check performs the SAML login and evaluates the resulting token TTL.
func (s *SAMLLoginChecker) Check() error {
	resp, err := s.client.LoginWithSAML(vault.SAMLLoginRequest{
		Mount:        s.mount,
		RoleName:     s.roleName,
		SAMLResponse: s.samlResponse,
	})
	if err != nil {
		_ = s.notifier.Send(alert.NewAlert(
			fmt.Sprintf("SAML login failed for role %q: %v", s.roleName, err),
			alert.SeverityCritical,
		))
		return fmt.Errorf("saml login check: %w", err)
	}

	ttl := time.Duration(resp.LeaseDuration) * time.Second
	if ttl == 0 {
		_ = s.notifier.Send(alert.NewAlert(
			fmt.Sprintf("SAML login for role %q returned zero TTL", s.roleName),
			alert.SeverityCritical,
		))
		return nil
	}

	if ttl <= s.warnTTL {
		_ = s.notifier.Send(alert.NewAlert(
			fmt.Sprintf("SAML token for role %q expires soon (TTL: %s)", s.roleName, ttl),
			alert.SeverityWarning,
		))
	}
	return nil
}
