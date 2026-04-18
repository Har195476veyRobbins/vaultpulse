package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// NamespaceInfo holds metadata about a Vault namespace.
type NamespaceInfo struct {
	Path   string            `json:"path"`
	ID     string            `json:"id"`
	Meta   map[string]string `json:"custom_metadata"`
}

type namespacesResponse struct {
	Data struct {
		KeyInfo map[string]NamespaceInfo `json:"key_info"`
	} `json:"data"`
}

// ListNamespaces returns all child namespaces under the current namespace.
func (c *Client) ListNamespaces() ([]NamespaceInfo, error) {
	req, err := http.NewRequest(http.MethodGet, c.address+"/v1/sys/namespaces?list=true", nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("list namespaces: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("namespaces endpoint not found (Vault OSS does not support namespaces)")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	var out namespacesResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	result := make([]NamespaceInfo, 0, len(out.Data.KeyInfo))
	for _, ns := range out.Data.KeyInfo {
		result = append(result, ns)
	}
	return result, nil
}
