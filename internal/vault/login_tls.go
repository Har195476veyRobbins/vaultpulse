package vault

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
)

// TLSLoginRequest holds the parameters for TLS certificate-based login.
type TLSLoginRequest struct {
	Mount    string
	RoleName string
	CertPEM  []byte
	KeyPEM   []byte
}

// TLSLoginResponse contains the Vault token returned after a successful TLS login.
type TLSLoginResponse struct {
	ClientToken string
	LeaseDuration int
	Renewable     bool
}

// LoginWithTLS authenticates against Vault using a mutual-TLS client certificate.
func (c *Client) LoginWithTLS(ctx context.Context, req TLSLoginRequest) (*TLSLoginResponse, error) {
	if req.Mount == "" {
		req.Mount = "cert"
	}
	if len(req.CertPEM) == 0 || len(req.KeyPEM) == 0 {
		return nil, fmt.Errorf("vault: TLS login requires both CertPEM and KeyPEM")
	}

	cert, err := tls.X509KeyPair(req.CertPEM, req.KeyPEM)
	if err != nil {
		return nil, fmt.Errorf("vault: failed to parse TLS key pair: %w", err)
	}

	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	transport := &http.Transport{TLSClientConfig: tlsCfg}
	httpClient := &http.Client{Transport: transport}

	body := map[string]string{}
	if req.RoleName != "" {
		body["name"] = req.RoleName
	}

	path := fmt.Sprintf("/v1/auth/%s/login", req.Mount)
	var result struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int    `json:"lease_duration"`
			Renewable     bool   `json:"renewable"`
		} `json:"auth"`
	}

	if err := c.postWithClient(ctx, httpClient, path, body, &result); err != nil {
		return nil, fmt.Errorf("vault: TLS login failed: %w", err)
	}

	return &TLSLoginResponse{
		ClientToken:   result.Auth.ClientToken,
		LeaseDuration: result.Auth.LeaseDuration,
		Renewable:     result.Auth.Renewable,
	}, nil
}
