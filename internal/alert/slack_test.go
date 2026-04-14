package alert

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewAlert_Severities(t *testing.T) {
	cases := []struct {
		ttl      int
		wantSev  Severity
	}{
		{-1, SeverityCritical},
		{0, SeverityCritical},
		{1800, SeverityCritical},
		{7200, SeverityWarning},
		{172800, SeverityInfo},
	}

	for _, tc := range cases {
		a := NewAlert("secret/my-app/db", tc.ttl)
		if a.Severity != tc.wantSev {
			t.Errorf("TTL=%d: got severity %q, want %q", tc.ttl, a.Severity, tc.wantSev)
		}
		if a.Message == "" {
			t.Errorf("TTL=%d: expected non-empty message", tc.ttl)
		}
	}
}

func TestSlackNotifier_Send_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	notifier := NewSlackNotifier(server.URL)
	a := NewAlert("secret/app/token", 1800)

	if err := notifier.Send(a); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestSlackNotifier_Send_NonOKStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	notifier := NewSlackNotifier(server.URL)
	a := NewAlert("secret/app/token", 1800)

	if err := notifier.Send(a); err == nil {
		t.Fatal("expected error for non-2xx status, got nil")
	}
}

func TestSlackNotifier_Send_BadURL(t *testing.T) {
	notifier := NewSlackNotifier("http://127.0.0.1:0/invalid")
	a := NewAlert("secret/app/token", 1800)

	if err := notifier.Send(a); err == nil {
		t.Fatal("expected error for unreachable URL, got nil")
	}
}
