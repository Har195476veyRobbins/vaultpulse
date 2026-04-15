package alert

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPagerDutyNotifier_Send_Success(t *testing.T) {
	var received pdEvent

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer ts.Close()

	n := NewPagerDutyNotifier("test-key")
	n.endpointURL = ts.URL

	a := Alert{
		Message:  "secret /prod/db expires soon",
		Severity: SeverityCritical,
		FiredAt:  time.Now(),
	}

	if err := n.Send(a); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if received.RoutingKey != "test-key" {
		t.Errorf("routing key = %q, want %q", received.RoutingKey, "test-key")
	}
	if received.EventAction != "trigger" {
		t.Errorf("event_action = %q, want trigger", received.EventAction)
	}
	if received.Payload.Summary != a.Message {
		t.Errorf("summary = %q, want %q", received.Payload.Summary, a.Message)
	}
	if received.Payload.Source != "vaultpulse" {
		t.Errorf("source = %q, want vaultpulse", received.Payload.Source)
	}
}

func TestPagerDutyNotifier_Send_NonAcceptedStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer ts.Close()

	n := NewPagerDutyNotifier("bad-key")
	n.endpointURL = ts.URL

	err := n.Send(Alert{Message: "test", Severity: SeverityWarning, FiredAt: time.Now()})
	if err == nil {
		t.Fatal("expected error for non-202 status, got nil")
	}
}

func TestPagerDutyNotifier_Send_BadURL(t *testing.T) {
	n := NewPagerDutyNotifier("key")
	n.endpointURL = "http://127.0.0.1:0" // nothing listening

	err := n.Send(Alert{Message: "test", Severity: SeverityInfo, FiredAt: time.Now()})
	if err == nil {
		t.Fatal("expected connection error, got nil")
	}
}
