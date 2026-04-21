package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// TransitKeyInfo holds metadata about a Vault transit encryption key.
type TransitKeyInfo struct {
	Name            string
	Type            string
	DeletionAllowed bool
	Exportable      bool
	MinDecryptionVersion int
	MinEncryptionVersion int
	LatestVersion   int
}

type transitKeyResponse struct {
	Data struct {
		Type                 string `json:"type"`
		DeletionAllowed      bool   `json:"deletion_allowed"`
		Exportable           bool   `json:"exportable"`
		MinDecryptionVersion int    `json:"min_decryption_version"`
		MinEncryptionVersion int    `json:"min_encryption_version"`
		LatestVersion        int    `json:"latest_version"`
	} `json:"data"`
}

type transitKeysListResponse struct {
	Data struct {
		Keys []string `json:"keys"`
	} `json:"data"`
}

// ListTransitKeys returns the names of all transit keys under the given mount.
func (c *Client) ListTransitKeys(mount string) ([]string, error) {
	if mount == "" {
		mount = "transit"
	}
	url := fmt.Sprintf("%s/v1/%s/keys?list=true", c.address, mount)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("transit: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("transit: list keys: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("transit: list keys: unexpected status %d", resp.StatusCode)
	}

	var result transitKeysListResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("transit: decode list response: %w", err)
	}
	return result.Data.Keys, nil
}

// GetTransitKey returns metadata for a specific transit key.
func (c *Client) GetTransitKey(mount, name string) (*TransitKeyInfo, error) {
	if mount == "" {
		mount = "transit"
	}
	url := fmt.Sprintf("%s/v1/%s/keys/%s", c.address, mount, name)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("transit: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("transit: get key: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("transit: key %q not found", name)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("transit: get key: unexpected status %d", resp.StatusCode)
	}

	var result transitKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("transit: decode key response: %w", err)
	}

	return &TransitKeyInfo{
		Name:                 name,
		Type:                 result.Data.Type,
		DeletionAllowed:      result.Data.DeletionAllowed,
		Exportable:           result.Data.Exportable,
		MinDecryptionVersion: result.Data.MinDecryptionVersion,
		MinEncryptionVersion: result.Data.MinEncryptionVersion,
		LatestVersion:        result.Data.LatestVersion,
	}, nil
}
