package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// GitHubLoginResponse holds the Vault response for a GitHub auth login.
type GitHubLoginResponse struct {
	Auth struct {
		ClientToken   string `json:"client_token"`
		LeaseDuration int    `json:"lease_duration"`
		Renewable     bool   `json:"renewable"`
	} `json:"auth"`
}

// LoginWithGitHub authenticates against Vault using a GitHub personal access token.
// It returns the client token on success.
func (c *Client) LoginWithGitHub(token string) (*GitHubLoginResponse, error) {
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("github token must not be empty")
	}

	payload := fmt.Sprintf(`{"token":%q}`, token)
	url := fmt.Sprintf("%s/v1/auth/github/login", c.address)

	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("building github login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github login request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		return nil, errors.New("github login forbidden: invalid token or insufficient permissions")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github login returned unexpected status: %d", resp.StatusCode)
	}

	var result GitHubLoginResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding github login response: %w", err)
	}
	return &result, nil
}
