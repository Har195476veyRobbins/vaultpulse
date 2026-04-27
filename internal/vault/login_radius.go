package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// RADIUSLoginResult holds the auth response from a RADIUS login.
type RADIUSLoginResult struct {
	ClientToken string
	LeaseDuration int
	Renewable     bool
}

// LoginWithRADIUS authenticates against Vault using the RADIUS auth method.
// username and password are required. mount defaults to "radius" if empty.
func (c *Client) LoginWithRADIUS(username, password, mount string) (*RADIUSLoginResult, error) {
	if username == "" {
		return nil, errors.New("vault: RADIUS username must not be empty")
	}
	if password == "" {
		return nil, errors.New("vault: RADIUS password must not be empty")
	}
	if mount == "" {
		mount = "radius"
	}

	path := fmt.Sprintf("/v1/auth/%s/login/%s", mount, username)
	body, err := jsonBody(map[string]string{"password": password})
	if err != nil {
		return nil, fmt.Errorf("vault: failed to encode RADIUS login payload: %w", err)
	}

	resp, err := c.http.Post(c.address+path, "application/json", body)
	if err != nil {
		return nil, fmt.Errorf("vault: RADIUS login request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("vault: RADIUS login denied (status %d)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vault: unexpected status from RADIUS login: %d", resp.StatusCode)
	}

	var result struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int    `json:"lease_duration"`
			Renewable     bool   `json:"renewable"`
		} `json:"auth"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("vault: failed to decode RADIUS login response: %w", err)
	}

	return &RADIUSLoginResult{
		ClientToken:   result.Auth.ClientToken,
		LeaseDuration: result.Auth.LeaseDuration,
		Renewable:     result.Auth.Renewable,
	}, nil
}
