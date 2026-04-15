package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// SecretMetadata holds KV v2 metadata for a secret path.
type SecretMetadata struct {
	Path           string
	CurrentVersion int
	OldestVersion  int
	CreatedTime    time.Time
	UpdatedTime    time.Time
	MaxVersions    int
	DeletedAt      *time.Time
}

type metadataResponse struct {
	Data struct {
		CurrentVersion int    `json:"current_version"`
		OldestVersion  int    `json:"oldest_version"`
		MaxVersions    int    `json:"max_versions"`
		CreatedTime    string `json:"created_time"`
		UpdatedTime    string `json:"updated_time"`
		Versions       map[string]struct {
			DeletionTime string `json:"deletion_time"`
			Destroyed    bool   `json:"destroyed"`
		} `json:"versions"`
	} `json:"data"`
}

// GetKVMetadata fetches KV v2 metadata for the given mount and secret path.
func (c *Client) GetKVMetadata(mount, secretPath string) (*SecretMetadata, error) {
	url := fmt.Sprintf("%s/v1/%s/metadata/%s", c.address, mount, secretPath)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("building metadata request: %w", err)
	}
	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("metadata request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("secret metadata not found: %s/%s", mount, secretPath)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d fetching metadata", resp.StatusCode)
	}

	var body metadataResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decoding metadata response: %w", err)
	}

	meta := &SecretMetadata{
		Path:           secretPath,
		CurrentVersion: body.Data.CurrentVersion,
		OldestVersion:  body.Data.OldestVersion,
		MaxVersions:    body.Data.MaxVersions,
	}

	if t, err := time.Parse(time.RFC3339Nano, body.Data.CreatedTime); err == nil {
		meta.CreatedTime = t
	}
	if t, err := time.Parse(time.RFC3339Nano, body.Data.UpdatedTime); err == nil {
		meta.UpdatedTime = t
	}

	currentKey := fmt.Sprintf("%d", body.Data.CurrentVersion)
	if v, ok := body.Data.Versions[currentKey]; ok && v.DeletionTime != "" {
		if t, err := time.Parse(time.RFC3339Nano, v.DeletionTime); err == nil {
			meta.DeletedAt = &t
		}
	}

	return meta, nil
}
