package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type LDAPLoginRequest struct {
	Password string `json:"password"`
}

type LDAPLoginResponse struct {
	Auth struct {
		ClientToken string `json:"client_token"`
		LeaseDuration int    `json:"lease_duration"`
	} `json:"auth"`
}

// LoginWithLDAP authenticates using LDAP credentials and returns a Vault token.
func (c *Client) LoginWithLDAP(username, password string) (string, error) {
	if strings.TrimSpace(username) == "" {
		return "", fmt.Errorf("ldap username must not be empty")
	}
	if strings.TrimSpace(password) == "" {
		return "", fmt.Errorf("ldap password must not be empty")
	}

	body, err := json.Marshal(LDAPLoginRequest{Password: password})
	if err != nil {
		return "", fmt.Errorf("marshal ldap login request: %w", err)
	}

	path := fmt.Sprintf("/v1/auth/ldap/login/%s", username)
	resp, err := c.rawPost(path, body)
	if err != nil {
		return "", fmt.Errorf("ldap login request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		return "", fmt.Errorf("ldap login forbidden: invalid credentials")
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ldap login unexpected status: %d", resp.StatusCode)
	}

	var result LDAPLoginResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode ldap login response: %w", err)
	}

	if result.Auth.ClientToken == "" {
		return "", fmt.Errorf("ldap login returned empty token")
	}

	return result.Auth.ClientToken, nil
}
