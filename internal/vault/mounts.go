package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// MountInfo holds basic information about a Vault mount.
type MountInfo struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	Accessor    string `json:"accessor"`
}

// ListMounts returns all secret and auth mounts from Vault.
func (c *Client) ListMounts() (map[string]MountInfo, error) {
	req, err := http.NewRequest(http.MethodGet, c.address+"/v1/sys/mounts", nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("list mounts: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list mounts: unexpected status %d", resp.StatusCode)
	}

	var result map[string]MountInfo
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode mounts: %w", err)
	}
	return result, nil
}
