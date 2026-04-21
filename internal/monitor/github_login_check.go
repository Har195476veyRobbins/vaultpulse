package monitor

import (
	"fmt"
	"time"

	"github.com/yourusername/vaultpulse/internal/alert"
	"github.com/yourusername/vaultpulse/internal/vault"
)

// GitHubLoginChecker verifies that a GitHub personal access token can
// successfully authenticate with Vault and that the resulting lease is
// not expiring soon.
type GitHubLoginChecker struct {
	client    *vault.Client
	token     string
	warnAfter time.Duration
	notifiers []alert.Notifier
}

// NewGitHubLoginChecker creates a GitHubLoginChecker.
func NewGitHubLoginChecker(client *vault.Client, token string, warnAfter time.Duration, notifiers []alert.Notifier) *GitHubLoginChecker {
	return &GitHubLoginChecker{
		client:    client,
		token:     token,
		warnAfter: warnAfter,
		notifiers: notifiers,
	}
}

// Check attempts a GitHub login and evaluates the resulting lease duration.
func (g *GitHubLoginChecker) Check() error {
	resp, err := g.client.LoginWithGitHub(g.token)
	if err != nil {
		a := alert.NewAlert(
			"vault/auth/github",
			fmt.Sprintf("GitHub login failed: %v", err),
			alert.SeverityCritical,
		)
		g.fire(a)
		return err
	}

	lease := time.Duration(resp.Auth.LeaseDuration) * time.Second

	if lease == 0 {
		a := alert.NewAlert(
			"vault/auth/github",
			"GitHub auth token has no TTL — may be non-renewable",
			alert.SeverityWarning,
		)
		g.fire(a)
		return nil
	}

	if lease <= g.warnAfter {
		severity := alert.SeverityWarning
		if lease <= g.warnAfter/2 {
			severity = alert.SeverityCritical
		}
		a := alert.NewAlert(
			"vault/auth/github",
			fmt.Sprintf("GitHub auth token expiring soon: %s remaining", lease.Round(time.Second)),
			severity,
		)
		g.fire(a)
	}
	return nil
}

func (g *GitHubLoginChecker) fire(a alert.Alert) {
	for _, n := range g.notifiers {
		_ = n.Send(a)
	}
}
