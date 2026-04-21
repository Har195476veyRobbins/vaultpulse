package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// GCPLoginRequest holds the parameters required for GCP IAM auth login.
type GCPLoginRequest struct {
	Role string `json:"role"`
	JWT  string `json:"jwt"`
}

// GCPLoginResponse holds the token returned after successful GCP login.
type GCPLoginResponse struct {
	Auth struct {
		ClientToken string `json:"client_tokenLeaseDuration int    `json:"lease_duration"`
		Renewable     bool   `json:"renewable"`
	} `json:"auth"`
}

// LoginWithGCP authenticates to Vault using the GCP IAM auth method.
func (c *Client) LoginWithGCP(role, jwt, mountPath string) (*GCPLoginResponse, error) {
	if role == "" {
		return nil, errors.New("gcp login: role must not be empty")
	}
	if jwt == "" {
		return nil, errors.New("gcp login: jwt must not be empty")
	}
	if mountPath == "" {
		mountPath = "gcp"
	}

	body, err := json.Marshal(GCPLoginRequest{Role: role, JWT: jwt})
	if err != nil {
		return nil, fmt.Errorf("gcp login: marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/v1/auth/%s/login", c.address, mountPath)
	resp, err := c.http.Post(url, "application/json", strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("gcp login: http post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gcp login: unexpected status %d", resp.StatusCode)
	}

	var result GCPLoginResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("gcp login: decode response: %w", err)
	}
	return &result, nil
}
