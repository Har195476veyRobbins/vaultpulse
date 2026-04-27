package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// OIDCLoginRequest holds credentials for OIDC auth method login.
type OIDCLoginRequest struct {
	Role  string
	Token string // OIDC ID token (JWT)
	Mount string // defaults to "oidc"
}

// OIDCLoginResponse holds the Vault token returned after a successful OIDC login.
type OIDCLoginResponse struct {
	ClientToken   string
	LeaseDuration int
	Renewable     bool
}

// LoginWithOIDC authenticates against Vault using the OIDC auth method.
func (c *Client) LoginWithOIDC(ctx context.Context, req OIDCLoginRequest) (*OIDCLoginResponse, error) {
	if req.Role == "" {
		return nil, fmt.Errorf("oidc login: role must not be empty")
	}
	if req.Token == "" {
		return nil, fmt.Errorf("oidc login: token must not be empty")
	}

	mount := req.Mount
	if mount == "" {
		mount = "oidc"
	}

	body := fmt.Sprintf(`{"role":%q,"jwt":%q}`, req.Role, req.Token)
	url := fmt.Sprintf("%s/v1/auth/%s/login", strings.TrimRight(c.address, "/"), mount)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("oidc login: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		httpReq.Header.Set("X-Vault-Token", c.token)
	}

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("oidc login: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusBadRequest {
		return nil, fmt.Errorf("oidc login: vault returned %d", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc login: unexpected status %d", resp.StatusCode)
	}

	var payload struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int    `json:"lease_duration"`
			Renewable     bool   `json:"renewable"`
		} `json:"auth"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("oidc login: decode response: %w", err)
	}

	return &OIDCLoginResponse{
		ClientToken:   payload.Auth.ClientToken,
		LeaseDuration: payload.Auth.LeaseDuration,
		Renewable:     payload.Auth.Renewable,
	}, nil
}
