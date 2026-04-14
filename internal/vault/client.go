package vault

import (
	"context"
	"fmt"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

// SecretMeta holds metadata about a Vault secret relevant to expiry.
type SecretMeta struct {
	Path      string
	ExpiresAt time.Time
	TTL       time.Duration
}

// Client wraps the Vault API client with helpers for VaultPulse.
type Client struct {
	api *vaultapi.Client
}

// NewClient creates a new Vault client using the provided address and token.
func NewClient(address, token string) (*Client, error) {
	cfg := vaultapi.DefaultConfig()
	cfg.Address = address

	c, err := vaultapi.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("creating vault api client: %w", err)
	}

	c.SetToken(token)

	return &Client{api: c}, nil
}

// GetSecretMeta reads the metadata for a KV v2 secret at the given path
// and returns expiry information derived from the secret's lease duration.
func (c *Client) GetSecretMeta(ctx context.Context, path string) (*SecretMeta, error) {
	secret, err := c.api.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("reading secret at %q: %w", path, err)
	}
	if secret == nil {
		return nil, fmt.Errorf("secret not found at path %q", path)
	}

	ttl := time.Duration(secret.LeaseDuration) * time.Second
	var expiresAt time.Time
	if ttl > 0 {
		expiresAt = time.Now().Add(ttl)
	}

	return &SecretMeta{
		Path:      path,
		ExpiresAt: expiresAt,
		TTL:       ttl,
	}, nil
}

// IsExpiringSoon returns true when the secret expires within the given threshold.
func (m *SecretMeta) IsExpiringSoon(threshold time.Duration) bool {
	if m.ExpiresAt.IsZero() {
		return false
	}
	return time.Until(m.ExpiresAt) <= threshold
}
