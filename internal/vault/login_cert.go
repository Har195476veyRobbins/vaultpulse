package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// CertLoginRequest holds TLS certificate auth parameters.
type CertLoginRequest struct {
	CertRoleName string
}

// CertLoginResponse holds the resulting Vault token.
type CertLoginResponse struct {
	ClientToken string
	LeaseDuration int
}

// LoginWithCert authenticates using a TLS client certificate.
func (c *Client) LoginWithCert(req CertLoginRequest) (*CertLoginResponse, error) {
	if req.CertRoleName == "" {
		return nil, fmt.Errorf("cert role name must not be empty")
	}

	path := fmt.Sprintf("%s/v1/auth/cert/login", c.address)
	body := map[string]string{"name": req.CertRoleName}

	payload, err := jsonBody(body)
	if err != nil {
		return nil, fmt.Errorf("encoding request: %w", err)
	}

	httpReq, err := http.NewRequest(http.MethodPost, path, payload)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("cert login request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("cert login forbidden: check role and certificate")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cert login: unexpected status %d", resp.StatusCode)
	}

	var result struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int    `json:"lease_duration"`
		} `json:"auth"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding cert login response: %w", err)
	}

	return &CertLoginResponse{
		ClientToken:   result.Auth.ClientToken,
		LeaseDuration: result.Auth.LeaseDuration,
	}, nil
}
