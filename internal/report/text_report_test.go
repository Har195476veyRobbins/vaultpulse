package report

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestReport_WriteText_ContainsHeaders(t *testing.T) {
	r := New(sampleSecrets())
	var buf bytes.Buffer

	if err := r.WriteText(&buf); err != nil {
		t.Fatalf("WriteText returned error: %v", err)
	}

	out := buf.String()
	for _, want := range []string{"PATH", "STATUS", "EXPIRES AT", "TTL (hours)", "Summary:"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected output to contain %q, got:\n%s", want, out)
		}
	}
}

func TestReport_WriteText_StatusLabels(t *testing.T) {
	secrets := sampleSecrets()
	r := New(secrets)
	var buf bytes.Buffer

	if err := r.WriteText(&buf); err != nil {
		t.Fatalf("WriteText returned error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "EXPIRING") {
		t.Errorf("expected EXPIRING label in output")
	}
	if !strings.Contains(out, "OK") {
		t.Errorf("expected OK label in output")
	}
}

func TestReport_WriteText_ContainsPaths(t *testing.T) {
	secrets := sampleSecrets()
	r := New(secrets)
	var buf bytes.Buffer

	if err := r.WriteText(&buf); err != nil {
		t.Fatalf("WriteText returned error: %v", err)
	}

	out := buf.String()
	for _, s := range secrets {
		if !strings.Contains(out, s.Path) {
			t.Errorf("expected path %q in output", s.Path)
		}
	}
}

func TestReport_WriteText_ExpiredLabel(t *testing.T) {
	secrets := sampleSecrets()
	// Override one secret to be expired
	secrets[0].IsExpired = true
	secrets[0].IsExpiring = false
	secrets[0].ExpiresAt = time.Now().Add(-1 * time.Hour)

	r := New(secrets)
	var buf bytes.Buffer

	if err := r.WriteText(&buf); err != nil {
		t.Fatalf("WriteText returned error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "EXPIRED") {
		t.Errorf("expected EXPIRED label in output")
	}
}
