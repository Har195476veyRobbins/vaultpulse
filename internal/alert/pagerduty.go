package alert

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const pagerDutyEventsURL = "https://events.pagerduty.com/v2/enqueue"

// PagerDutyNotifier sends alerts to PagerDuty via the Events API v2.
type PagerDutyNotifier struct {
	RoutingKey string
	Client     *http.Client
	EventsURL  string // overridable for testing
}

type pdPayload struct {
	RoutingKey  string    `json:"routing_key"`
	EventAction string    `json:"event_action"`
	Payload     pdDetails `json:"payload"`
}

type pdDetails struct {
	Summary  string `json:"summary"`
	Severity string `json:"severity"`
	Source   string `json:"source"`
}

// NewPagerDutyNotifier creates a PagerDutyNotifier with a default HTTP client.
func NewPagerDutyNotifier(routingKey string) *PagerDutyNotifier {
	return &PagerDutyNotifier{
		RoutingKey: routingKey,
		Client:     &http.Client{Timeout: 10 * time.Second},
		EventsURL:  pagerDutyEventsURL,
	}
}

// Send triggers a PagerDuty incident for the given alert.
func (p *PagerDutyNotifier) Send(a Alert) error {
	severity := "warning"
	if a.Severity == SeverityCritical {
		severity = "critical"
	}

	pd := pdPayload{
		RoutingKey:  p.RoutingKey,
		EventAction: "trigger",
		Payload: pdDetails{
			Summary:  a.Message,
			Severity: severity,
			Source:   a.SecretPath,
		},
	}

	body, err := json.Marshal(pd)
	if err != nil {
		return fmt.Errorf("pagerduty: marshal payload: %w", err)
	}

	resp, err := p.Client.Post(p.EventsURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("pagerduty: http post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("pagerduty: unexpected status code %d", resp.StatusCode)
	}

	return nil
}
