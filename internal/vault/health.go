package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// HealthStatus represents the health state of a Vault instance.
type HealthStatus struct {
	Initialized bool   `json:"initialized"`
	Sealed      bool   `json:"sealed"`
	Standby     bool   `json:"standby"`
	Version     string `json:"version"`
	ClusterName string `json:"cluster_name"`
	CheckedAt   time.Time
}

// IsHealthy returns true when Vault is initialised, unsealed, and active.
func (h HealthStatus) IsHealthy() bool {
	return h.Initialized && !h.Sealed && !h.Standby
}

// CheckHealth queries the Vault /v1/sys/health endpoint and returns the
// current health status. It does NOT return an error for non-200 responses
// because Vault uses status codes semantically (429 = standby, 501 = not
// initialised, 503 = sealed), so we parse the body in all cases.
func (c *Client) CheckHealth(ctx context.Context) (HealthStatus, error) {
	url := fmt.Sprintf("%s/v1/sys/health", c.address)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return HealthStatus{}, fmt.Errorf("vault health: build request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return HealthStatus{}, fmt.Errorf("vault health: request failed: %w", err)
	}
	defer resp.Body.Close()

	var status HealthStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return HealthStatus{}, fmt.Errorf("vault health: decode response: %w", err)
	}

	status.CheckedAt = time.Now().UTC()
	return status, nil
}
