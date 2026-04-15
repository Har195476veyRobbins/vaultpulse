package alert

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const defaultPagerDutyEndpoint = "https://events.pagerduty.com/v2/enqueue"

type pagerDutyNotifier struct {
	routingKey string
	endpoint   string
	client     *http.Client
}

type pdPayload struct {
	Summary   string `json:"summary"`
	Severity  string `json:"severity"`
	Source    string `json:"source"`
	Timestamp string `json:"timestamp"`
	CustomDetails map[string]string `json:"custom_details,omitempty"`
}

type pdEvent struct {
	RoutingKey  string    `json:"routing_key"`
	EventAction string    `json:"event_action"`
	Payload     pdPayload `json:"payload"`
}

// NewPagerDutyNotifier creates a new PagerDuty notifier using the given routing key.
func NewPagerDutyNotifier(routingKey string) Notifier {
	return &pagerDutyNotifier{
		routingKey: routingKey,
		endpoint:   defaultPagerDutyEndpoint,
		client:     &http.Client{Timeout: 10 * time.Second},
	}
}

func (p *pagerDutyNotifier) Send(a *Alert) error {
	severity := "warning"
	if a.Severity == SeverityCritical {
		severity = "critical"
	}

	event := pdEvent{
		RoutingKey:  p.routingKey,
		EventAction: "trigger",
		Payload: pdPayload{
			Summary:   fmt.Sprintf("%s: %s", a.Title, a.Message),
			Severity:  severity,
			Source:    "vaultpulse",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			CustomDetails: map[string]string{
				"secret_path": a.SecretPath,
				"expires_at":  a.ExpiresAt.UTC().Format(time.RFC3339),
			},
		},
	}

	body, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("pagerduty: marshal event: %w", err)
	}

	resp, err := p.client.Post(p.endpoint, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("pagerduty: send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("pagerduty: unexpected status %d", resp.StatusCode)
	}

	return nil
}
