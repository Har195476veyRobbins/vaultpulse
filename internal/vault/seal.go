package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// SealStatus represents the seal state of a Vault node.
type SealStatus struct {
	Sealed      bool   `json:"sealed"`
	Initialized bool   `json:"initialized"`
	T           int    `json:"t"`
	N           int    `json:"n"`
	Progress    int    `json:"progress"`
	Version     string `json:"version"`
	ClusterName string `json:"cluster_name"`
}

// GetSealStatus queries /v1/sys/seal-status and returns the current seal state.
func (c *Client) GetSealStatus() (*SealStatus, error) {
	url := fmt.Sprintf("%s/v1/sys/seal-status", c.address)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("seal status: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("seal status: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("seal status: unexpected status %d", resp.StatusCode)
	}

	var status SealStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, fmt.Errorf("seal status: decode response: %w", err)
	}

	return &status, nil
}
