package monitor

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/yourusername/vaultpulse/internal/alert"
	"github.com/yourusername/vaultpulse/internal/audit"
	"github.com/yourusername/vaultpulse/internal/vault"
)

// SnapshotChecker verifies that a Vault raft snapshot can be taken successfully.
type SnapshotChecker struct {
	client   *vault.Client
	notifier alert.Notifier
	auditor  audit.Auditor
}

// NewSnapshotChecker creates a SnapshotChecker.
func NewSnapshotChecker(c *vault.Client, n alert.Notifier, a audit.Auditor) *SnapshotChecker {
	return &SnapshotChecker{client: c, notifier: n, auditor: a}
}

// Check attempts to stream a snapshot and alerts if unavailable or on error.
func (s *SnapshotChecker) Check(ctx context.Context) error {
	var buf bytes.Buffer
	status, err := s.client.TakeSnapshot(ctx, &buf)
	if err != nil {
		_ = s.auditor.Log(ctx, "snapshot_check_error", map[string]any{"error": err.Error()})
		a := alert.NewAlert(
			"Vault Snapshot Unavailable",
			fmt.Sprintf("Failed to take Vault snapshot: %v", err),
			alert.SeverityCritical,
		)
		return s.notifier.Send(ctx, a)
	}

	if !status.Available {
		_ = s.auditor.Log(ctx, "snapshot_not_available", nil)
		a := alert.NewAlert(
			"Vault Snapshot Not Available",
			"Raft snapshot endpoint returned 404; storage backend may not support snapshots.",
			alert.SeverityWarning,
		)
		return s.notifier.Send(ctx, a)
	}

	_ = s.auditor.Log(ctx, "snapshot_ok", map[string]any{
		"size_bytes": status.SizeBytes,
		"taken_at":   time.Now().UTC().Format(time.RFC3339),
	})
	return nil
}
