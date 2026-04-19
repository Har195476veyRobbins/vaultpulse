package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// KubernetesLoginRequest holds credentials for Kubernetes auth.
type KubernetesLoginRequest struct {
	Role string `json:"role"`
	J  string `json:"jwt"`
}

// LoginWithKubernetes authenticates using the Kubernetes auth method.
func (c *Client) LoginWithKubernetes(role, jwt, mountPath string) (string, error) {
	if role == "" {
		return "", errors.New("role must not be empty")
	}
	if jwt == "" {
		return "", errors.New("jwt must not be empty")
	}
	if mountPath == "" {
		mountPath = "kubernetes"
	}

	body, err := json.Marshal(KubernetesLoginRequest{Role: role, JWT: jwt})
	if err != nil {
		return "", fmt.Errorf("marshal error: %w", err)
	}

	url := fmt.Sprintf("%s/v1/auth/%s/login", c.Address, mountPath)
	resp, err := c.HTTP.Post(url, "application/json", strings.NewReader(string(body)))
	if err != nil {
		return "", fmt.Errorf("kubernetes login request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusBadRequest {
		return "", fmt.Errorf("kubernetes login failed: HTTP %d", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var result struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode error: %w", err)
	}
	return result.Auth.ClientToken, nil
}
