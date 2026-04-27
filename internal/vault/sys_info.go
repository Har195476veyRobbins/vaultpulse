package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// SysInfo holds key system information returned by Vault's /v1/sys/host-info endpoint.
type SysInfo struct {
	CPUCount  int    `json:"cpu_count"`
	Hostname  string `json:"hostname"`
	OS        string `json:"os"`
	OSVersion string `json:"os_version"`
	Uptime    uint64 `json:"uptime"`
}

type sysInfoResponse struct {
	Data SysInfo `json:"data"`
}

// GetSysInfo retrieves host-level system information from Vault.
// Requires a token with access to sys/host-info.
func (c *Client) GetSysInfo() (*SysInfo, error) {
	url := fmt.Sprintf("%s/v1/sys/host-info", c.address)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("sys_info: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sys_info: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sys_info: unexpected status %d", resp.StatusCode)
	}

	var result sysInfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("sys_info: decode response: %w", err)
	}

	return &result.Data, nil
}
