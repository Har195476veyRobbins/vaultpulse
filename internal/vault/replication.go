package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// ReplicationStatus holds the DR and performance replication state.
type ReplicationStatus struct {
	DR          ReplicationMode `json:"dr"`
	Performance ReplicationMode `json:"performance"`
}

// ReplicationMode describes a single replication mode.
type ReplicationMode struct {
	Mode    string `json:"mode"`
	State   string `json:"state"`
	Primary string `json:"primary_cluster_addr,omitempty"`
}

type replicationResponse struct {
	Data ReplicationStatus `json:"data"`
}

// GetReplicationStatus returns the current replication status from Vault.
func (c *Client) GetReplicationStatus(ctx context.Context) (*ReplicationStatus, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.address+"/v1/sys/replication/status", nil)
	if err != nil {
		return nil, fmt.Errorf("replication status: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("replication status: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("replication status: unexpected status %d", resp.StatusCode)
	}

	var out replicationResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("replication status: decode: %w", err)
	}
	return &out.Data, nil
}
