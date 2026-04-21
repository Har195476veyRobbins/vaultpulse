package monitor

import (
	"fmt"

	"github.com/wryfi/vaultpulse/internal/alert"
	"github.com/wryfi/vaultpulse/internal/vault"
)

// PluginChecker alerts when non-builtin (external) plugins are registered,
// which may indicate unexpected or unaudited extensions.
type PluginChecker struct {
	client    *vault.Client
	notifiers []alert.Notifier
}

// NewPluginChecker creates a PluginChecker.
func NewPluginChecker(client *vault.Client, notifiers []alert.Notifier) *PluginChecker {
	return &PluginChecker{client: client, notifiers: notifiers}
}

// Check lists plugins and fires a warning alert for each non-builtin plugin found.
func (p *PluginChecker) Check() error {
	plugins, err := p.client.ListPlugins()
	if err != nil {
		return fmt.Errorf("plugin check: %w", err)
	}

	for _, plugin := range plugins {
		if plugin.Builtin {
			continue
		}
		a := alert.NewAlert(
			alert.SeverityWarning,
			"external-plugin",
			fmt.Sprintf("Non-builtin plugin registered: %s (type=%s, version=%s)",
				plugin.Name, plugin.Type, plugin.Version),
		)
		if err := p.notify(a); err != nil {
			return err
		}
	}
	return nil
}

// notify sends the given alert to all configured notifiers, returning the first
// error encountered.
func (p *PluginChecker) notify(a alert.Alert) error {
	for _, n := range p.notifiers {
		if err := n.Send(a); err != nil {
			return fmt.Errorf("plugin check notify: %w", err)
		}
	}
	return nil
}
