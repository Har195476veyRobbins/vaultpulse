package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// TokenInfo holds metadata about the current Vault token.
type TokenInfo struct {
	Accessor   string
	DisplayName string
	Policies   []string
	TTL        time.Duration
	Renewable  bool
	ExpireTime time.Time
}

type tokenLookupResponse struct {
	Data struct {
		Accessor    string   `json:"accessor"`
		DisplayName string   `json:"display_name"`
		Policies    []string `json:"policies"`
		TTL         int      `json:"ttl"`
		Renewable   bool     `json:"renewable"`
		ExpireTime  string   `json:"expire_time"`
	} `json:"data"`
}

// LookupSelfToken calls auth/token/lookup-self and returns token metadata.
func (c *Client) LookupSelfToken(ctx context.Context) (*TokenInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.address+"/v1/auth/token/lookup-self", nil)
	if err != nil {
		return nil, fmt.Errorf("vault: build token lookup request: %w", err)
	}
	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vault: token lookup request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vault: token lookup returned status %d", resp.StatusCode)
	}

	var result tokenLookupResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("vault: decode token lookup response: %w", err)
	}

	info := &TokenInfo{
		Accessor:    result.Data.Accessor,
		DisplayName: result.Data.DisplayName,
		Policies:    result.Data.Policies,
		TTL:         time.Duration(result.Data.TTL) * time.Second,
		Renewable:   result.Data.Renewable,
	}

	if result.Data.ExpireTime != "" {
		if t, err := time.Parse(time.RFC3339, result.Data.ExpireTime); err == nil {
			info.ExpireTime = t
		}
	}

	return info, nil
}
