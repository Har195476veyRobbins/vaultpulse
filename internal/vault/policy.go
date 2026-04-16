package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// PolicyInfo holds metadata about a Vault policy.
type PolicyInfo struct {
	Name      string
	Rules     string
	FetchedAt time.Time
}

// ListPolicies returns the names of all ACL policies in Vault.
func (c *Client) ListPolicies(ctx context.Context) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.address+"/v1/sys/policies/acl?list=true", nil)
	if err != nil {
		return nil, fmt.Errorf("build list policies request: %w", err)
	}
	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("list policies: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list policies: unexpected status %d", resp.StatusCode)
	}

	var body struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decode list policies: %w", err)
	}
	return body.Data.Keys, nil
}

// GetPolicy returns the rules for a named ACL policy.
func (c *Client) GetPolicy(ctx context.Context, name string) (*PolicyInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.address+"/v1/sys/policies/acl/"+name, nil)
	if err != nil {
		return nil, fmt.Errorf("build get policy request: %w", err)
	}
	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get policy %s: %w", name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("policy %q not found", name)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get policy %s: unexpected status %d", name, resp.StatusCode)
	}

	var body struct {
		Data struct {
			Policy string `json:"policy"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decode policy: %w", err)
	}
	return &PolicyInfo{Name: name, Rules: body.Data.Policy, FetchedAt: time.Now()}, nil
}
