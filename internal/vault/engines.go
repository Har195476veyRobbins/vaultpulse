package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// MountInfo represents a single secret engine mount.
type MountInfo struct {
	Path        string
	Type        string
	Description string
	Accessor    string
}

// mountsResponse mirrors the Vault API response for sys/mounts.
type mountsResponse struct {
	Data map[string]struct {
		Type        string `json:"type"`
		Description string `json:"description"`
		Accessor    string `json:"accessor"`
	} `json:"data"`
}

// ListSecretEngines returns all enabled secret engine mounts from Vault.
func (c *Client) ListSecretEngines() ([]MountInfo, error) {
	req, err := http.NewRequest(http.MethodGet, c.address+"/v1/sys/mounts", nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d listing mounts", resp.StatusCode)
	}

	var result mountsResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	mounts := make([]MountInfo, 0, len(result.Data))
	for path, info := range result.Data {
		mounts = append(mounts, MountInfo{
			Path:        path,
			Type:        info.Type,
			Description: info.Description,
			Accessor:    info.Accessor,
		})
	}
	return mounts, nil
}
