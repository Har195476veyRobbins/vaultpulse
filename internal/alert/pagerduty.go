package alert

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const pagerDutyEventURL = "https://events.pagerduty.com/v2/enqueue"

// PagerDutyNotifier sends alerts to PagerDuty via the Events API v2.
type PagerDutyNotifier struct {
	integrationKey string
	httpClient     *http.Client
	endpointURL    string
}

type pdPayload struct {
	Summary   string `json:"summary"`
	Severity  string `json:"severity"`
	Timestamp string `json:"timestamp"`
	Source    string `json:"source"`
}

type pdEvent struct {
	RoutingKey  string    `json:"routing_key"`
	EventAction string    `json:"event_action"`
	Payload     pdPayload `json:"payload"`
}

// NewPagerDutyNotifier creates a PagerDutyNotifier with the given integration key.
func NewPagerDutyNotifier(integrationKey string) *PagerDutyNotifier {
	return &PagerDutyNotifier{
		integrationKey: integrationKey,
		httpClient:     &http.Client{Timeout: 10 * time.Second},
		endpointURL:    pagerDutyEventURL,
	}
}

// Send delivers an Alert to PagerDuty.
func (p *PagerDutyNotifier) Send(a Alert) error {
	event := pdEvent{
		RoutingKey:  p.integrationKey,
		EventAction: "trigger",
		Payload: pdPayload{
			Summary:   a.Message,
			Severity:  string(a.Severity),
			Timestamp: a.FiredAt.UTC().Format(time.RFC3339),
			Source:    "vaultpulse",
		},
	}

	body, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("pagerduty: marshal event: %w", err)
	}

	resp, err := p.httpClient.Post(p.endpointURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("pagerduty: send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("pagerduty: unexpected status %d", resp.StatusCode)
	}
	return nil
}
