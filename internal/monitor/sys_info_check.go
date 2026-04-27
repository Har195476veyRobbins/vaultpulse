package monitor

import (
	"fmt"

	"github.com/yourusername/vaultpulse/internal/alert"
	"github.com/yourusername/vaultpulse/internal/vault"
)

// SysInfoChecker checks Vault host system information and alerts if the
// hostname is empty or the reported uptime is zero (indicating a potential
// misconfiguration or unreachable host-info endpoint).
type SysInfoChecker struct {
	client *vault.Client
	notify []alert.Notifier
}

// NewSysInfoChecker creates a SysInfoChecker using the provided Vault client
// and notifiers.
func NewSysInfoChecker(client *vault.Client, notifiers []alert.Notifier) *SysInfoChecker {
	return &SysInfoChecker{
		client: client,
		notify: notifiers,
	}
}

// Check fetches Vault host info and fires alerts when anomalies are detected.
func (s *SysInfoChecker) Check() error {
	info, err := s.client.GetSysInfo()
	if err != nil {
		a := alert.NewAlert(
			"vault.sys_info",
			fmt.Sprintf("Failed to retrieve Vault host info: %v", err),
			alert.SeverityCritical,
		)
		for _, n := range s.notify {
			_ = n.Send(a)
		}
		return err
	}

	if info.Hostname == "" {
		a := alert.NewAlert(
			"vault.sys_info.hostname",
			"Vault host-info returned an empty hostname",
			alert.SeverityWarning,
		)
		for _, n := range s.notify {
			_ = n.Send(a)
		}
	}

	if info.Uptime == 0 {
		a := alert.NewAlert(
			"vault.sys_info.uptime",
			fmt.Sprintf("Vault host '%s' reports zero uptime — node may have just restarted", info.Hostname),
			alert.SeverityWarning,
		)
		for _, n := range s.notify {
			_ = n.Send(a)
		}
	}

	return nil
}
