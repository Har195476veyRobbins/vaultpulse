package vault

import (
	"errors"
	"fmt"
	"net/http"
)

// AzureLoginRequest holds the parameters for Azure auth login.
type AzureLoginRequest struct {
	Role           string `json:"role"`
	JWT            string `json:"jwt"`
	SubscriptionID string `json:"subscription_id"`
	ResourceGroupName string `json:"resource_group_name"`
	VMName         string `json:"vm_name,omitempty"`
	VMSSName       string `json:"vmss_name,omitempty"`
}

// AzureLoginResponse holds the token returned after a successful Azure login.
type AzureLoginResponse struct {
	ClientToken string
	LeaseDuration int
	Renewable     bool
}

// LoginWithAzure authenticates to Vault using the Azure auth method.
func (c *Client) LoginWithAzure(req AzureLoginRequest) (*AzureLoginResponse, error) {
	if req.Role == "" {
		return nil, errors.New("azure login: role is required")
	}
	if req.JWT == "" {
		return nil, errors.New("azure login: jwt is required")
	}
	if req.SubscriptionID == "" {
		return nil, errors.New("azure login: subscription_id is required")
	}
	if req.ResourceGroupName == "" {
		return nil, errors.New("azure login: resource_group_name is required")
	}

	path := fmt.Sprintf("/v1/auth/azure/login")
	resp, err := c.post(path, req)
	if err != nil {
		return nil, fmt.Errorf("azure login: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("azure login: forbidden (check role and credentials)")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("azure login: unexpected status %d", resp.StatusCode)
	}

	var body struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int    `json:"lease_duration"`
			Renewable     bool   `json:"renewable"`
		} `json:"auth"`
	}
	if err := decode(resp.Body, &body); err != nil {
		return nil, fmt.Errorf("azure login: decode response: %w", err)
	}

	return &AzureLoginResponse{
		ClientToken:   body.Auth.ClientToken,
		LeaseDuration: body.Auth.LeaseDuration,
		Renewable:     body.Auth.Renewable,
	}, nil
}
