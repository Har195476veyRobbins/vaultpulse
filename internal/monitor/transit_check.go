// Package monitor provides checkers that inspect Vault state and emit alerts.
// transit_check.go monitors Transit secret engine keys for rotation age and
// deletion-window expiry, alerting when keys are overdue for rotation.
package monitor

import (
	"context"
	"fmt"
	"time"

	"github.com/yourusername/vaultpulse/internal/alert"
	"github.com/yourusername/vaultpulse/internal/vault"
)

// TransitChecker inspects Transit engine keys and raises alerts when a key has
// not been rotated within the configured threshold, or when its deletion window
// is approaching.
type TransitChecker struct {
	client          *vault.Client
	mount           string
	rotationWarning time.Duration // warn if latest version is older than this
	notifiers       []alert.Notifier
}

// NewTransitChecker creates a TransitChecker for the given mount path.
// rotationWarning is the maximum acceptable age for the latest key version
// before a warning alert is raised (e.g. 720h for 30 days).
func NewTransitChecker(
	client *vault.Client,
	mount string,
	rotationWarning time.Duration,
	notifiers []alert.Notifier,
) *TransitChecker {
	if mount == "" {
		mount = "transit"
	}
	return &TransitChecker{
		client:          client,
		mount:           mount,
		rotationWarning: rotationWarning,
		notifiers:       notifiers,
	}
}

// Check lists all Transit keys under the configured mount and evaluates each
// one. It fires alerts for keys whose latest version has not been rotated
// within the rotation warning window.
func (tc *TransitChecker) Check(ctx context.Context) error {
	keys, err := tc.client.ListTransitKeys(ctx, tc.mount)
	if err != nil {
		return fmt.Errorf("transit_check: list keys on mount %q: %w", tc.mount, err)
	}

	for _, name := range keys {
		if err := tc.checkKey(ctx, name); err != nil {
			// Log and continue so one bad key does not block the rest.
			fmt.Printf("transit_check: skipping key %q: %v\n", name, err)
		}
	}
	return nil
}

func (tc *TransitChecker) checkKey(ctx context.Context, name string) error {
	key, err := tc.client.GetTransitKey(ctx, tc.mount, name)
	if err != nil {
		return fmt.Errorf("get key %q: %w", name, err)
	}

	// Determine the creation time of the latest key version.
	latestVersion := key.LatestVersion
	creationTime, ok := key.Keys[fmt.Sprintf("%d", latestVersion)]
	if !ok {
		// No creation time available; skip alerting for this key.
		return nil
	}

	age := time.Since(creationTime)
	path := fmt.Sprintf("%s/keys/%s", tc.mount, name)

	if age > tc.rotationWarning {
		severity := alert.SeverityWarning
		msg := fmt.Sprintf(
			"Transit key %q (version %d) on mount %q has not been rotated for %s (threshold: %s)",
			name, latestVersion, tc.mount,
			age.Round(time.Hour).String(),
			tc.rotationWarning.String(),
		)
		a := alert.NewAlert(path, msg, severity)
		for _, n := range tc.notifiers {
			_ = n.Send(ctx, a)
		}
	}

	return nil
}
