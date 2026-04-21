package monitor

import (
	"fmt"
	"time"

	"github.com/yourusername/vaultpulse/internal/alert"
	"github.com/yourusername/vaultpulse/internal/vault"
)

// GCPLoginChecker verifies that Vault's GCP auth method is reachable
// and returns a valid token with an acceptable TTL.
type GCPLoginChecker struct {
	client    *vault.Client
	role      string
	jwt       string
	mountPath string
	warnTTL   time.Duration
	notifiers []alert.Notifier
}

// NewGCPLoginChecker creates a GCPLoginChecker.
func NewGCPLoginChecker(
	client *vault.Client,
	role, jwt, mountPath string,
	warnTTL time.Duration,
	notifiers []alert.Notifier,
) *GCPLoginChecker {
	if mountPath == "" {
		mountPath = "gcp"
	}
	return &GCPLoginChecker{
		client:    client,
		role:      role,
		jwt:       jwt,
		mountPath: mountPath,
		warnTTL:   warnTTL,
		notifiers: notifiers,
	}
}

// Check performs the GCP login and evaluates the returned token TTL.
func (g *GCPLoginChecker) Check() error {
	resp, err := g.client.LoginWithGCP(g.role, g.jwt, g.mountPath)
	if err != nil {
		a := alert.NewAlert(
			fmt.Sprintf("GCP login failed for role %q: %v", g.role, err),
			alert.SeverityCritical,
			"gcp-login",
		)
		for _, n := range g.notifiers {
			_ = n.Send(a)
		}
		return err
	}

	ttl := time.Duration(resp.Auth.LeaseDuration) * time.Second
	if ttl > 0 && ttl < g.warnTTL {
		a := alert.NewAlert(
			fmt.Sprintf("GCP login token for role %q expires in %s", g.role, ttl),
			alert.SeverityWarning,
			"gcp-login",
		)
		for _, n := range g.notifiers {
			_ = n.Send(a)
		}
	}
	return nil
}
