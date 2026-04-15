package audit_test

import (
	"testing"

	"github.com/yourusername/vaultpulse/internal/audit"
)

func TestNoopLogger_NeverErrors(t *testing.T) {
	n := audit.NewNoop()

	types := []audit.EventType{
		audit.EventSecretChecked,
		audit.EventAlertSent,
		audit.EventAlertFailed,
		audit.EventScanStarted,
		audit.EventScanCompleted,
	}

	for _, et := range types {
		if err := n.Log(et, "some/path", "msg", map[string]string{"k": "v"}); err != nil {
			t.Errorf("NoopLogger.Log(%q) returned error: %v", et, err)
		}
	}
}

func TestNoopLogger_ImplementsAuditor(t *testing.T) {
	// Compile-time check that NoopLogger satisfies the Auditor interface.
	var _ audit.Auditor = audit.NewNoop()
}

func TestLogger_ImplementsAuditor(t *testing.T) {
	// Compile-time check that Logger satisfies the Auditor interface.
	var _ audit.Auditor = audit.New(nil)
}
