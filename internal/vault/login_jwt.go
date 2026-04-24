package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// JWTLoginRequest holds the parameters for JWT/OIDC authentication.
type JWTLoginRequest struct {
	Role  string
	JWT   string
	Mount string // defaults to "jwt"
}

// JWTLoginResponse holds the token returned by a successful JWT login.
type JWTLoginResponse struct {
	ClientToken   string
	LeaseDuration int
	Renewable     bool
}

// LoginWithJWT authenticates against Vault using the JWT/OIDC auth method.
func (c *Client) LoginWithJWT(ctx context.Context, req JWTLoginRequest) (*JWTLoginResponse, error) {
	if req.Role == "" {
		return nil, fmt.Errorf("jwt login: role must not be empty")
	}
	if req.JWT == "" {
		return nil, fmt.Errorf("jwt login: jwt must not be empty")
	}

	mount := req.Mount
	if mount == "" {
		mount = "jwt"
	}

	body := fmt.Sprintf(`{"role":%q,"jwt":%q}`, req.Role, req.JWT)
	url := fmt.Sprintf("%s/v1/auth/%s/login", strings.TrimRight(c.address, "/"), mount)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("jwt login: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Vault-Token", c.token)

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("jwt login: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("jwt login: unauthorized (status %d)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwt login: unexpected status %d", resp.StatusCode)
	}

	var result struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int    `json:"lease_duration"`
			Renewable     bool   `json:"renewable"`
		} `json:"auth"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("jwt login: decode response: %w", err)
	}

	return &JWTLoginResponse{
		ClientToken:   result.Auth.ClientToken,
		LeaseDuration: result.Auth.LeaseDuration,
		Renewable:     result.Auth.Renewable,
	}, nil
}
