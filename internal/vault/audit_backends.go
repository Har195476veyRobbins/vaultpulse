package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// AuditBackend represents a single Vault audit device.
type AuditBackend struct {
	Type        string `json:"type"`
	Path        string `json:"path"`
	Description string `json:"description"`
	Enabled     bool
}

// ListAuditBackends returns all enabled audit backends from Vault.
func (c *Client) ListAuditBackends() ([]AuditBackend, error) {
	req, err := http.NewRequest(http.MethodGet, c.address+"/v1/sys/audit", nil)
	if err != nil {
		return nil, fmt.Errorf("audit backends: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("audit backends: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("audit backends: unexpected status %d", resp.StatusCode)
	}

	var raw map[string]struct {
		Type        string `json:"type"`
		Description string `json:"description"`
	}{}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("audit backends: decode: %w", err)
	}

	var backends []AuditBackend
	for path, info := range raw {
		backends = append(backends, AuditBackend{
			Type:        info.Type,
			Path:        path,
			Description: info.Description,
			Enabled:     true,
		})
	}
	return backends, nil
}
