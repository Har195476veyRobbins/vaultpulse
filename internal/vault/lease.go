package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// LeaseInfo holds details about a Vault lease.
type LeaseInfo struct {
	LeaseID       string
	Renewable     bool
	LeaseDuration time.Duration
	ExpireTime    time.Time
}

type lookupLeaseResponse struct {
	Data struct {
		ID            string `json:"id"`
		Renewable     bool   `json:"renewable"`
		TTL           int    `json:"ttl"`
		ExpireTime    string `json:"expire_time"`
	} `json:"data"`
}

// LookupLease retrieves metadata for a given lease ID.
func (c *Client) LookupLease(ctx context.Context, leaseID string) (*LeaseInfo, error) {
	if leaseID == "" {
		return nil, fmt.Errorf("lease id must not be empty")
	}

	body, err := jsonBody(map[string]string{"lease_id": leaseID})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut,
		c.address+"/v1/sys/leases/lookup", body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("lease not found: %s", leaseID)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d from lease lookup", resp.StatusCode)
	}

	var out lookupLeaseResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}

	expire, _ := time.Parse(time.RFC3339, out.Data.ExpireTime)
	return &LeaseInfo{
		LeaseID:       out.Data.ID,
		Renewable:     out.Data.Renewable,
		LeaseDuration: time.Duration(out.Data.TTL) * time.Second,
		ExpireTime:    expire,
	}, nil
}
