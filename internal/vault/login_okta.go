package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// OktaLoginRequest holds credentials for Okta authentication.
type OktaLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// OktaLoginResponse holds the Vault token returned after Okta login.
type OktaLoginResponse struct {
	Auth struct {
		ClientToken   string `json:"client_token"`
		LeaseDuration int    `json:"lease_duration"`
		Renewable     bool   `json:"renewable"`
	} `json:"auth"`
}

// LoginWithOkta authenticates against Vault using the Okta auth method.
// It returns the client token on success.
func (c *Client) LoginWithOkta(username, password string) (*OktaLoginResponse, error) {
	if username == "" {
		return nil, errors.New("okta login: username must not be empty")
	}
	if password == "" {
		return nil, errors.New("okta login: password must not be empty")
	}

	path := fmt.Sprintf("%s/v1/auth/okta/login/%s", c.address, username)

	body, err := jsonEncode(OktaLoginRequest{Username: username, Password: password})
	if err != nil {
		return nil, fmt.Errorf("okta login: encode request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, path, body)
	if err != nil {
		return nil, fmt.Errorf("okta login: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("okta login: do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		return nil, errors.New("okta login: forbidden — invalid credentials")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("okta login: unexpected status %d", resp.StatusCode)
	}

	var result OktaLoginResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("okta login: decode response: %w", err)
	}
	return &result, nil
}
