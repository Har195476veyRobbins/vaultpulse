package alert

import "fmt"

// Severity represents the urgency level of an alert.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

// Alert holds the data for a secret expiry notification.
type Alert struct {
	SecretPath string
	TTL        int // remaining seconds
	Severity   Severity
	Message    string
}

// Notifier is the interface implemented by all alert backends.
type Notifier interface {
	Send(alert Alert) error
}

// NewAlert builds an Alert from a secret path and remaining TTL.
func NewAlert(secretPath string, ttlSeconds int) Alert {
	var sev Severity
	var msg string

	switch {
	case ttlSeconds <= 0:
		sev = SeverityCritical
		msg = fmt.Sprintf("Secret '%s' has EXPIRED.", secretPath)
	case ttlSeconds < 3600:
		sev = SeverityCritical
		msg = fmt.Sprintf("Secret '%s' expires in less than 1 hour (%ds remaining).", secretPath, ttlSeconds)
	case ttlSeconds < 86400:
		sev = SeverityWarning
		msg = fmt.Sprintf("Secret '%s' expires in less than 24 hours (%ds remaining).", secretPath, ttlSeconds)
	default:
		sev = SeverityInfo
		msg = fmt.Sprintf("Secret '%s' expires in %ds.", secretPath, ttlSeconds)
	}

	return Alert{
		SecretPath: secretPath,
		TTL:        ttlSeconds,
		Severity:   sev,
		Message:    msg,
	}
}
