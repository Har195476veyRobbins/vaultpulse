package vault

import (
	"errors"
	"fmt"
	"net/http"
)

// SAMLLoginRequest holds the parameters required for SAML authentication.
type SAMLLoginRequest struct {
	Mount      string // default: "saml"
	RoleName   string
	SAMLResponse string
}

// SAMLLoginResponse holds the token returned after a successful SAML login.
type SAMLLoginResponse struct {
	ClientToken string
	LeaseDuration int
	Renewable   bool
}

// LoginWithSAML authenticates against Vault using the SAML auth method.
func (c *Client) LoginWithSAML(req SAMLLoginRequest) (*SAMLLoginResponse, error) {
	if req.RoleName == "" {
		return nil, errors.New("saml login: role name must not be empty")
	}
	if req.SAMLResponse == "" {
		return nil, errors.New("saml login: SAMLResponse must not be empty")
	}
	mount := req.Mount
	if mount == "" {
		mount = "saml"
	}

	path := fmt.Sprintf("/v1/auth/%s/login", mount)
	body := map[string]string{
		"role":          req.RoleName,
		"saml_response": req.SAMLResponse,
	}

	resp, err := c.postJSON(path, body)
	if err != nil {
		return nil, fmt.Errorf("saml login: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("saml login: authentication failed (status %d)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("saml login: unexpected status %d", resp.StatusCode)
	}

	var result struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int    `json:"lease_duration"`
			Renewable     bool   `json:"renewable"`
		} `json:"auth"`
	}
	if err := decodeJSON(resp.Body, &result); err != nil {
		return nil, fmt.Errorf("saml login: failed to decode response: %w", err)
	}

	return &SAMLLoginResponse{
		ClientToken:   result.Auth.ClientToken,
		LeaseDuration: result.Auth.LeaseDuration,
		Renewable:     result.Auth.Renewable,
	}, nil
}
