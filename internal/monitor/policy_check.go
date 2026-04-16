package monitor

import (
	"context"
	"fmt"
	"log"

	"github.com/yourusername/vaultpulse/internal/alert"
	"github.com/yourusername/vaultpulse/internal/vault"
)

// PolicyChecker checks for Vault policies that are empty or suspiciously permissive.
type PolicyChecker struct {
	client    *vault.Client
	notifiers []alert.Notifier
}

// NewPolicyChecker creates a PolicyChecker.
func NewPolicyChecker(client *vault.Client, notifiers []alert.Notifier) *PolicyChecker {
	return &PolicyChecker{client: client, notifiers: notifiers}
}

// Check lists all policies and alerts on any that are empty.
func (pc *PolicyChecker) Check(ctx context.Context) error {
	policies, err := pc.client.ListPolicies(ctx)
	if err != nil {
		return fmt.Errorf("policy check list: %w", err)
	}

	for _, name := range policies {
		info, err := pc.client.GetPolicy(ctx, name)
		if err != nil {
			log.Printf("policy check: skipping %s: %v", name, err)
			continue
		}
		if info.Rules == "" {
			a := alert.NewAlert(
				fmt.Sprintf("Vault policy %q has no rules defined", name),
				alert.SeverityWarning,
				"policy:"+name,
			)
			for _, n := range pc.notifiers {
				if err := n.Send(ctx, a); err != nil {
					log.Printf("policy check: notify error: %v", err)
				}
			}
		}
	}
	return nil
}
