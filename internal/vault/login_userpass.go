package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// UserpassLoginResponse holds the token returned from a userpass login.
type UserpassLoginResponse struct {
	Auth struct {
		ClientToken string `json:"client_token"`
		LeaseDuration int    `json:"lease_duration"`
		Renewable     bool   `json:"renewable"`
	} `json:"auth"`
}

// LoginWithUserpass authenticates against Vault using the userpass auth method
// and returns the resulting client token.
func (c *Client) LoginWithUserpass(username, password string) (string, error) {
	if username == "" {
		return "", fmt.Errorf("username must not be empty")
	}
	if password == "" {
		return "", fmt.Errorf("password must not be empty")
	}

	body := fmt.Sprintf(`{"password":%q}`, password)
	url := fmt.Sprintf("%s/v1/auth/userpass/login/%s", strings.TrimRight(c.address, "/"), username)

	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("userpass login request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		return "", fmt.Errorf("userpass login forbidden: invalid credentials")
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("userpass login: unexpected status %d", resp.StatusCode)
	}

	var result UserpassLoginResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode userpass login response: %w", err)
	}

	if result.Auth.ClientToken == "" {
		return "", fmt.Errorf("userpass login: empty client token in response")
	}

	return result.Auth.ClientToken, nil
}
