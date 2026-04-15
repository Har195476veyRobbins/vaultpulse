package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// AuthMethod represents a Vault authentication method.
type AuthMethod string

const (
	AuthMethodToken      AuthMethod = "token"
	AuthMethodAppRole    AuthMethod = "approle"
	AuthMethodKubernetes AuthMethod = "kubernetes"
)

// AppRoleCredentials holds the role_id and secret_id for AppRole auth.
type AppRoleCredentials struct {
	RoleID   string
	SecretID string
}

// AppRoleAuthResponse is the parsed response from the AppRole login endpoint.
type AppRoleAuthResponse struct {
	Auth struct {
		ClientToken   string    `json:"client_token"`
		LeaseDuration int       `json:"lease_duration"`
		Renewable     bool      `json:"renewable"`
	} `json:"auth"`
}

// LoginResult contains the token and its expiry derived from the auth response.
type LoginResult struct {
	Token     string
	ExpiresAt time.Time
	Renewable bool
}

// LoginWithAppRole authenticates to Vault using the AppRole method and returns
// a LoginResult containing the issued client token.
func (c *Client) LoginWithAppRole(creds AppRoleCredentials) (*LoginResult, error) {
	if creds.RoleID == "" {
		return nil, fmt.Errorf("approle: role_id must not be empty")
	}

	payload := fmt.Sprintf(`{"role_id":%q,"secret_id":%q}`, creds.RoleID, creds.SecretID)
	url := strings.TrimRight(c.address, "/") + "/v1/auth/approle/login"

	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("approle: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("approle: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("approle: unexpected status %d", resp.StatusCode)
	}

	var authResp AppRoleAuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return nil, fmt.Errorf("approle: decode response: %w", err)
	}

	if authResp.Auth.ClientToken == "" {
		return nil, fmt.Errorf("approle: empty client token in response")
	}

	return &LoginResult{
		Token:     authResp.Auth.ClientToken,
		ExpiresAt: time.Now().Add(time.Duration(authResp.Auth.LeaseDuration) * time.Second),
		Renewable: authResp.Auth.Renewable,
	}, nil
}
