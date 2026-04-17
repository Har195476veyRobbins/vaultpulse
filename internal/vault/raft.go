package vault

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// RaftServer represents a single Raft peer.
type RaftServer struct {
	NodeID    string `json:"node_id"`
	Address   string `json:"address"`
	Leader    bool   `json:"leader"`
	Voter     bool   `json:"voter"`
	Protocol  string `json:"protocol_version"`
}

// RaftStatus holds the Raft cluster configuration.
type RaftStatus struct {
	Servers []RaftServer `json:"servers"`
}

type raftResponse struct {
	Data RaftStatus `json:"data"`
}

// GetRaftStatus returns the current Raft autopilot state from Vault.
func (c *Client) GetRaftStatus() (*RaftStatus, error) {
	url := fmt.Sprintf("%s/v1/sys/storage/raft/autopilot/state", c.address)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("raft: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("raft: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("raft: unexpected status %d", resp.StatusCode)
	}

	var out raftResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("raft: decode response: %w", err)
	}
	return &out.Data, nil
}
