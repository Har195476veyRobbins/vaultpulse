package alert

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPagerDutyNotifier_Send_Success(t *testing.T) {
	var received map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected application/json content type")
		}
		json.NewDecoder(r.Body).Decode(&received)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	notifier := &pagerDutyNotifier{
		routingKey: "test-routing-key",
		endpoint:   server.URL,
		client:     server.Client(),
	}

	alert := &Alert{
		Title:     "Secret expiring soon",
		Message:   "secret/myapp/db expires in 24h",
		Severity:  SeverityWarning,
		SecretPath: "secret/myapp/db",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	if err := notifier.Send(alert); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if received["routing_key"] != "test-routing-key" {
		t.Errorf("expected routing_key to be set, got %v", received["routing_key"])
	}
	if received["event_action"] != "trigger" {
		t.Errorf("expected event_action=trigger, got %v", received["event_action"])
	}
}

func TestPagerDutyNotifier_Send_NonAcceptedStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	notifier := &pagerDutyNotifier{
		routingKey: "key",
		endpoint:   server.URL,
		client:     server.Client(),
	}

	alert := &Alert{
		Title:    "Test",
		Message:  "msg",
		Severity: SeverityCritical,
	}

	if err := notifier.Send(alert); err == nil {
		t.Error("expected error for non-202 status, got nil")
	}
}

func TestPagerDutyNotifier_Send_BadURL(t *testing.T) {
	notifier := &pagerDutyNotifier{
		routingKey: "key",
		endpoint:   "http://127.0.0.1:0",
		client:     &http.Client{},
	}

	alert := &Alert{
		Title:    "Test",
		Message:  "msg",
		Severity: SeverityWarning,
	}

	if err := notifier.Send(alert); err == nil {
		t.Error("expected error for bad URL, got nil")
	}
}
