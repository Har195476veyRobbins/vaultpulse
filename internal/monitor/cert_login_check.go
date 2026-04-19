package monitor

import (
	"fmt"
	"time"

	"github.com/yourusername/vaultpulse/internal/alert"
	"github.com/yourusername/vaultpulse/internal/vault"
)

// CertLoginChecker verifies TLS certificate auth and checks token TTL.
type CertLoginChecker struct {
	client       *vault.Client
	roleName     string
	warnDuration time.Duration
}

// NewCertLoginChecker creates a CertLoginChecker.
func NewCertLoginChecker(client *vault.Client, roleName string, warnDuration time.Duration) *CertLoginChecker {
	return &CertLoginChecker{
		client:       client,
		roleName:     roleName,
		warnDuration: warnDuration,
	}
}

// Check performs the cert login and evaluates the resulting token TTL.
func (c *CertLoginChecker) Check() ([]alert.Alert, error) {
	resp, err := c.client.LoginWithCert(vault.CertLoginRequest{CertRoleName: c.roleName})
	if err != nil {
		return nil, fmt.Errorf("cert login check: %w", err)
	}

	ttl := time.Duration(resp.LeaseDuration) * time.Second
	path := fmt.Sprintf("auth/cert/role/%s", c.roleName)

	if ttl == 0 {
		return []alert.Alert{
			alert.NewAlert(path, "cert login returned zero TTL", alert.Critical),
		}, nil
	}

	if ttl <= c.warnDuration {
		return []alert.Alert{
			alert.NewAlert(path,
				fmt.Sprintf("cert login token expiring soon: TTL %s", ttl),
				alert.Warning),
		}, nil
	}

	return nil, nil
}
