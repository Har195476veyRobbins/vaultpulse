package audit_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/yourusername/vaultpulse/internal/audit"
)

func TestLog_WritesJSONLine(t *testing.T) {
	var buf bytes.Buffer
	l := audit.New(&buf)

	err := l.Log(audit.EventSecretChecked, "secret/my-app", "secret checked", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	line := strings.TrimSpace(buf.String())
	if line == "" {
		t.Fatal("expected output, got empty")
	}

	var e audit.Event
	if err := json.Unmarshal([]byte(line), &e); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if e.Type != audit.EventSecretChecked {
		t.Errorf("expected type %q, got %q", audit.EventSecretChecked, e.Type)
	}
	if e.Path != "secret/my-app" {
		t.Errorf("expected path %q, got %q", "secret/my-app", e.Path)
	}
	if e.Message != "secret checked" {
		t.Errorf("unexpected message: %q", e.Message)
	}
	if e.Timestamp.IsZero() {
		t.Error("expected non-zero timestamp")
	}
}

func TestLog_WithMeta(t *testing.T) {
	var buf bytes.Buffer
	l := audit.New(&buf)

	meta := map[string]string{"severity": "critical", "notifier": "slack"}
	err := l.Log(audit.EventAlertSent, "secret/db", "alert dispatched", meta)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var e audit.Event
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &e); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if e.Meta["severity"] != "critical" {
		t.Errorf("expected meta severity=critical, got %q", e.Meta["severity"])
	}
	if e.Meta["notifier"] != "slack" {
		t.Errorf("expected meta notifier=slack, got %q", e.Meta["notifier"])
	}
}

func TestLog_MultipleEvents(t *testing.T) {
	var buf bytes.Buffer
	l := audit.New(&buf)

	events := []audit.EventType{
		audit.EventScanStarted,
		audit.EventSecretChecked,
		audit.EventScanCompleted,
	}
	for _, et := range events {
		if err := l.Log(et, "", string(et), nil); err != nil {
			t.Fatalf("log error: %v", err)
		}
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}
}
