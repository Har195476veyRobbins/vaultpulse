package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// PluginInfo holds metadata about a registered Vault plugin.
type PluginInfo struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Version string `json:"version"`
	Builtin bool   `json:"builtin"`
}

// PluginListResponse is the raw API response from Vault.
type PluginListResponse struct {
	Data struct {
		Detailed []PluginInfo `json:"detailed"`
	} `json:"data"`
}

// ListPlugins returns all registered plugins from the Vault catalog.
func (c *Client) ListPlugins() ([]PluginInfo, error) {
	req, err := http.NewRequest(http.MethodGet, c.address+"/v1/sys/plugins/catalog?detailed=true", nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("list plugins: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list plugins: unexpected status %d", resp.StatusCode)
	}

	var out PluginListResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode plugins: %w", err)
	}
	return out.Data.Detailed, nil
}
