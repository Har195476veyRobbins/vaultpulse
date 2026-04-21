package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// AWSLoginRequest holds the parameters for AWS IAM authentication.
type AWSLoginRequest struct {
	Role                    string `json:"role"`
	IAMHTTPRequestMethod    string `json:"iam_http_request_method"`
	IAMRequestURL           string `json:"iam_request_url"`
	IAMRequestBody          string `json:"iam_request_body"`
	IAMRequestHeaders       string `json:"iam_request_headers"`
}

// AWSLoginResponse holds the Vault token returned after a successful AWS login.
type AWSLoginResponse struct {
	Auth struct {
		ClientToken string `json:"client_token"`
		LeaseDuration int    `json:"lease_duration"`
		Renewable     bool   `json:"renewable"`
	} `json:"auth"`
}

// LoginWithAWS authenticates with Vault using the AWS IAM method and returns
// the client token on success.
func (c *Client) LoginWithAWS(req AWSLoginRequest) (string, error) {
	if strings.TrimSpace(req.Role) == "" {
		return "", errors.New("aws login: role must not be empty")
	}
	if strings.TrimSpace(req.IAMRequestURL) == "" {
		return "", errors.New("aws login: iam_request_url must not be empty")
	}

	body, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("aws login: marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/v1/auth/aws/login", c.Address)
	resp, err := c.HTTP.Post(url, "application/json", strings.NewReader(string(body)))
	if err != nil {
		return "", fmt.Errorf("aws login: http post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("aws login: unexpected status %d", resp.StatusCode)
	}

	var result AWSLoginResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("aws login: decode response: %w", err)
	}

	if result.Auth.ClientToken == "" {
		return "", errors.New("aws login: empty client token in response")
	}

	return result.Auth.ClientToken, nil
}
