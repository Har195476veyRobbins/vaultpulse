package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// OCILoginRequest holds the parameters for OCI IAM authentication.
type OCILoginRequest struct {
	Role        string
	RequestURL  string
	RequestBody string
	Headers     map[string]string
}

// OCILoginResponse holds the token and lease info returned after OCI login.
type OCILoginResponse struct {
	ClientToken string
	LeaseDuration int
	Renewable   bool
}

// LoginWithOCI authenticates to Vault using the OCI IAM auth method.
func (c *Client) LoginWithOCI(ctx context.Context, req OCILoginRequest) (*OCILoginResponse, error) {
	if strings.TrimSpace(req.Role) == "" {
		return nil, fmt.Errorf("oci login: role must not be empty")
	}
	if strings.TrimSpace(req.RequestURL) == "" {
		return nil, fmt.Errorf("oci login: request_url must not be empty")
	}

	body := map[string]interface{}{
		"role":         req.Role,
		"request_url":  req.RequestURL,
		"request_body": req.RequestBody,
		"request_headers": req.Headers,
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("oci login: marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/v1/auth/oci/login/%s", c.address, req.Role)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(payload)))
	if err != nil {
		return nil, fmt.Errorf("oci login: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		httpReq.Header.Set("X-Vault-Token", c.token)
	}

	httpClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("oci login: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("oci login: forbidden (403)")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oci login: unexpected status %d", resp.StatusCode)
	}

	var result struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int    `json:"lease_duration"`
			Renewable     bool   `json:"renewable"`
		} `json:"auth"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("oci login: decode response: %w", err)
	}

	return &OCILoginResponse{
		ClientToken:   result.Auth.ClientToken,
		LeaseDuration: result.Auth.LeaseDuration,
		Renewable:     result.Auth.Renewable,
	}, nil
}
