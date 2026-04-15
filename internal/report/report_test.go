package report_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/yourusername/vaultpulse/internal/report"
)

func sampleSecrets() []report.SecretStatus {
	now := time.Now().UTC()
	return []report.SecretStatus{
		{
			Path:      "secret/db/password",
			ExpiresAt: now.Add(48 * time.Hour),
			TTL:       48 * time.Hour,
			Expiring:  false,
			Expired:   false,
		},
		{
			Path:      "secret/api/key",
			ExpiresAt: now.Add(2 * time.Hour),
			TTL:       2 * time.Hour,
			Expiring:  true,
			Expired:   false,
		},
		{
			Path:      "secret/old/token",
			ExpiresAt: now.Add(-1 * time.Hour),
			TTL:       0,
			Expiring:  false,
			Expired:   true,
		},
	}
}

func TestNew_SetsGeneratedAt(t *testing.T) {
	before := time.Now().UTC()
	r := report.New(sampleSecrets())
	after := time.Now().UTC()
	if r.GeneratedAt.Before(before) || r.GeneratedAt.After(after) {
		t.Errorf("GeneratedAt %v not in expected range", r.GeneratedAt)
	}
}

func TestReport_Summary(t *testing.T) {
	r := report.New(sampleSecrets())
	expiring, expired := r.Summary()
	if expiring != 1 {
		t.Errorf("expected 1 expiring, got %d", expiring)
	}
	if expired != 1 {
		t.Errorf("expected 1 expired, got %d", expired)
	}
}

func TestReport_WriteTo_ContainsPaths(t *testing.T) {
	r := report.New(sampleSecrets())
	var buf bytes.Buffer
	if err := r.WriteTo(&buf); err != nil {
		t.Fatalf("WriteTo error: %v", err)
	}
	out := buf.String()
	for _, s := range sampleSecrets() {
		if !strings.Contains(out, s.Path) {
			t.Errorf("output missing path %q", s.Path)
		}
	}
	if !strings.Contains(out, "EXPIRED") {
		t.Error("output missing EXPIRED status")
	}
	if !strings.Contains(out, "EXPIRING") {
		t.Error("output missing EXPIRING status")
	}
}

func TestReport_WriteJSON_ValidStructure(t *testing.T) {
	r := report.New(sampleSecrets())
	var buf bytes.Buffer
	if err := r.WriteJSON(&buf); err != nil {
		t.Fatalf("WriteJSON error: %v", err)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if _, ok := out["generated_at"]; !ok {
		t.Error("missing generated_at field")
	}
	summary, ok := out["summary"].(map[string]interface{})
	if !ok {
		t.Fatal("missing or invalid summary field")
	}
	if int(summary["expiring"].(float64)) != 1 {
		t.Errorf("expected summary.expiring=1")
	}
	if int(summary["expired"].(float64)) != 1 {
		t.Errorf("expected summary.expired=1")
	}
}
