package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// TokenLoginResponse holds the result of a token-based login lookup.
type TokenLoginResponse struct {
	ClientToken string
	Policies    []string
	TTL         time.Duration
	Renewable   bool
}

// LoginWithToken validates the given token and returns metadata about it.
func (c *Client) LoginWithToken(token string) (*TokenLoginResponse, error) {
	if token == "" {
		return nil, fmt.Errorf("token must not be empty")
	}

	req, err := http.NewRequest(http.MethodGet, c.address+"/v1/auth/token/lookup-self", nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", token)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("invalid or expired token (status %d)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var body struct {
		Data struct {
			ClientToken string   `json:"id"`
			Policies    []string `json:"policies"`
			TTL         int      `json:"ttl"`
			Renewable   bool     `json:"renewable"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &TokenLoginResponse{
		ClientToken: body.Data.ClientToken,
		Policies:    body.Data.Policies,
		TTL:         time.Duration(body.Data.TTL) * time.Second,
		Renewable:   body.Data.Renewable,
	}, nil
}
