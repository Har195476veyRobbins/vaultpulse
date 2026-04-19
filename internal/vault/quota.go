package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// QuotaRule represents a single rate-limit or lease-count quota rule.
type QuotaRule struct {
	Name      string  `json:"name"`
	Type      string  `json:"type"`
	Path      string  `json:"path"`
	MaxLeases int     `json:"max_leases"`
	Rate      float64 `json:"rate"`
}

// QuotaListResponse is the Vault API response for listing quotas.
type QuotaListResponse struct {
	Data struct {
		Keys []string `json:"keys"`
	} `json:"data"`
}

// ListQuotas returns all quota rule names from Vault.
func (c *Client) ListQuotas() ([]string, error) {
	req, err := http.NewRequest(http.MethodGet, c.address+"/v1/sys/quotas/rate-limit?list=true", nil)
	if err != nil {
		return nil, fmt.Errorf("quota list request: %w", err)
	}
	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("quota list: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return []string{}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("quota list: unexpected status %d", resp.StatusCode)
	}

	var out QuotaListResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("quota list decode: %w", err)
	}
	return out.Data.Keys, nil
}
