package monitor

import (
	"context"
	"fmt"

	"github.com/yourusername/vaultpulse/internal/alert"
	"github.com/yourusername/vaultpulse/internal/vault"
)

// AzureLoginConfig holds configuration for the Azure login checker.
type AzureLoginConfig struct {
	Role              string
	JWT               string
	SubscriptionID    string
	ResourceGroupName string
	VMName            string
}

// AzureLoginChecker verifies that an Azure auth login succeeds and the
// resulting token has a healthy TTL.
type AzureLoginChecker struct {
	client *vault.Client
	cfg    AzureLoginConfig
	notify alert.Notifier
}

// NewAzureLoginChecker creates a new AzureLoginChecker.
func NewAzureLoginChecker(client *vault.Client, cfg AzureLoginConfig, notifier alert.Notifier) *AzureLoginChecker {
	return &AzureLoginChecker{client: client, cfg: cfg, notify: notifier}
}

// Check performs the Azure login and alerts if the returned token lease is
// shorter than the warning threshold or if login fails entirely.
func (a *AzureLoginChecker) Check(ctx context.Context) error {
	resp, err := a.client.LoginWithAzure(vault.AzureLoginRequest{
		Role:              a.cfg.Role,
		JWT:               a.cfg.JWT,
		SubscriptionID:    a.cfg.SubscriptionID,
		ResourceGroupName: a.cfg.ResourceGroupName,
		VMName:            a.cfg.VMName,
	})
	if err != nil {
		notifyErr := a.notify.Send(ctx, alert.NewAlert(
			fmt.Sprintf("Azure login failed for role %q: %v", a.cfg.Role, err),
			alert.SeverityCritical,
		))
		if notifyErr != nil {
			return fmt.Errorf("azure login check: notify error: %w", notifyErr)
		}
		return fmt.Errorf("azure login check: %w", err)
	}

	const warnThreshold = 3600 // 1 hour
	if resp.LeaseDuration < warnThreshold {
		if err := a.notify.Send(ctx, alert.NewAlert(
			fmt.Sprintf("Azure token for role %q expiring soon: %ds remaining", a.cfg.Role, resp.LeaseDuration),
			alert.SeverityWarning,
		)); err != nil {
			return fmt.Errorf("azure login check: notify warning: %w", err)
		}
	}

	return nil
}
