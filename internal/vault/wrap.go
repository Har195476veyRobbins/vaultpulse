package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// WrapInfo holds metadata about a wrapped secret token.
type WrapInfo struct {
	Token           string    `json:"token"`
	Accessor        string    `json:"accessor"`
	TTL             int       `json:"ttl"`
	CreationTime    time.Time `json:"creation_time"`
	CreationPath    string    `json:"creation_path"`
	WrappedAccessor string    `json:"wrapped_accessor"`
}

type wrapLookupResponse struct {
	Data WrapInfo `json:"data"`
}

// LookupWrappingToken inspects a wrapping token and returns its WrapInfo.
func (c *Client) LookupWrappingToken(token string) (*WrapInfo, error) {
	if token == "" {
		return nil, fmt.Errorf("wrapping token must not be empty")
	}

	req, err := http.NewRequest(http.MethodPost, c.address+"/v1/sys/wrapping/lookup", nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("X-Vault-Token", token)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("lookup request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("wrapping token not found or already unwrapped")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var out wrapLookupResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	return &out.Data, nil
}
