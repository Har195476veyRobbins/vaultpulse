package alert

import (
	"context"
	"fmt"
	"time"
)

// Notifier is the interface that all alert backends must implement.
type Notifier interface {
	Send(ctx context.Context, a Alert) error
}

// Alert carries information about a secret that is nearing expiry.
type Alert struct {
	SecretPath string
	TTL        time.Duration
	Threshold  time.Duration
	Severity   string
	Message    string
}

// NewAlert constructs an Alert, deriving severity and a human-readable message
// from the remaining TTL relative to the warn threshold.
func NewAlert(path string, ttl, threshold time.Duration) Alert {
	severity := severityFor(ttl, threshold)
	msg := fmt.Sprintf(
		"Secret %q expires in %s (threshold: %s) — severity: %s",
		path,
		ttl.Round(time.Second),
		threshold.Round(time.Second),
		severity,
	)
	return Alert{
		SecretPath: path,
		TTL:        ttl,
		Threshold:  threshold,
		Severity:   severity,
		Message:    msg,
	}
}

// severityFor maps remaining TTL to a severity label.
func severityFor(ttl, threshold time.Duration) string {
	switch {
	case ttl <= 0:
		return "critical" // already expired
	case ttl <= threshold/4:
		return "critical"
	case ttl <= threshold/2:
		return "high"
	default:
		return "warning"
	}
}
