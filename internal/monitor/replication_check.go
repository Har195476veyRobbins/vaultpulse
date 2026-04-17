package monitor

import (
	"context"
	"fmt"

	"github.com/your-org/vaultpulse/internal/alert"
	"github.com/your-org/vaultpulse/internal/vault"
)

// ReplicationChecker monitors Vault replication health.
type ReplicationChecker struct {
	client *vault.Client
	notifiers []alert.Notifier
}

// NewReplicationChecker creates a ReplicationChecker.
func NewReplicationChecker(client *vault.Client, notifiers []alert.Notifier) *ReplicationChecker {
	return &ReplicationChecker{client: client, notifiers: notifiers}
}

// Check fetches replication status and fires alerts for degraded modes.
func (rc *ReplicationChecker) Check(ctx context.Context) error {
	rs, err := rc.client.GetReplicationStatus(ctx)
	if err != nil {
		return fmt.Errorf("replication check: %w", err)
	}

	rc.evaluate(ctx, "DR", rs.DR)
	rc.evaluate(ctx, "Performance", rs.Performance)
	return nil
}

func (rc *ReplicationChecker) evaluate(ctx context.Context, label string, mode vault.ReplicationMode) {
	if mode.Mode == "disabled" || mode.Mode == "" {
		return
	}
	if mode.State != "running" && mode.State != "stream-wals" {
		a := alert.NewAlert(
			fmt.Sprintf("Vault %s replication degraded", label),
			fmt.Sprintf("%s replication mode=%s state=%s", label, mode.Mode, mode.State),
			alert.SeverityCritical,
		)
		for _, n := range rc.notifiers {
			_ = n.Send(ctx, a)
		}
	}
}
