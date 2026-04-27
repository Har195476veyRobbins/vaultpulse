package monitor

import (
	"fmt"
	"log"

	"github.com/your-org/vaultpulse/internal/alert"
	"github.com/your-org/vaultpulse/internal/vault"
)

// EnginesChecker checks that expected secret engine mounts are present in Vault.
type EnginesChecker struct {
	client        *vault.Client
	notifiers     []alert.Notifier
	requiredTypes []string
}

// NewEnginesChecker creates an EnginesChecker that alerts when required engine
// types are absent from the Vault mount table.
func NewEnginesChecker(client *vault.Client, notifiers []alert.Notifier, required []string) *EnginesChecker {
	return &EnginesChecker{
		client:        client,
		notifiers:     notifiers,
		requiredTypes: required,
	}
}

// Check lists all mounted engines and fires a warning alert for each required
// engine type that is not found.
func (e *EnginesChecker) Check() error {
	mounts, err := e.client.ListSecretEngines()
	if err != nil {
		return fmt.Errorf("list secret engines: %w", err)
	}

	present := make(map[string]bool, len(mounts))
	for _, m := range mounts {
		present[m.Type] = true
	}

	for _, required := range e.requiredTypes {
		if present[required] {
			continue
		}
		a := alert.NewAlert(
			fmt.Sprintf("required secret engine type %q is not mounted", required),
			alert.SeverityWarning,
		)
		e.sendAlert(a)
	}
	return nil
}

// sendAlert delivers the given alert to all registered notifiers, logging any
// delivery errors without aborting the remaining notifiers.
func (e *EnginesChecker) sendAlert(a alert.Alert) {
	for _, n := range e.notifiers {
		if sendErr := n.Send(a); sendErr != nil {
			log.Printf("engines_check: notifier error: %v", sendErr)
		}
	}
}
