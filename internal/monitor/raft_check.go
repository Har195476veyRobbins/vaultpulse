package monitor

import (
	"fmt"

	"github.com/yourusername/vaultpulse/internal/alert"
	"github.com/yourusername/vaultpulse/internal/vault"
)

// RaftChecker monitors Raft cluster health.
type RaftChecker struct {
	client *vault.Client
	notifiers []alert.Notifier
}

// NewRaftChecker creates a new RaftChecker.
func NewRaftChecker(client *vault.Client, notifiers []alert.Notifier) *RaftChecker {
	return &RaftChecker{client: client, notifiers: notifiers}
}

// Check inspects Raft peer state and alerts if no leader is found or a voter is missing.
func (rc *RaftChecker) Check() error {
	status, err := rc.client.GetRaftStatus()
	if err != nil {
		return fmt.Errorf("raft check: %w", err)
	}

	leaderFound := false
	for _, s := range status.Servers {
		if s.Leader {
			leaderFound = true
			break
		}
	}

	if !leaderFound {
		a := alert.NewAlert(
			"raft/no-leader",
			"Vault Raft cluster has no leader",
			alert.SeverityCritical,
		)
		for _, n := range rc.notifiers {
			_ = n.Send(a)
		}
		return nil
	}

	for _, s := range status.Servers {
		if s.Voter && s.NodeID == "" {
			a := alert.NewAlert(
				"raft/unknown-voter",
				"Vault Raft cluster has a voter with no node ID",
				alert.SeverityWarning,
			)
			for _, n := range rc.notifiers {
				_ = n.Send(a)
			}
		}
	}

	return nil
}
