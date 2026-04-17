package vault

import (
	"context"
	"fmt"
	"io"
	"net/http"
)

// SnapshotStatus holds metadata about the latest Vault raft snapshot.
type SnapshotStatus struct {
	Available bool
	SizeBytes int64
}

// TakeSnapshot streams a Raft snapshot from Vault into the provided writer.
func (c *Client) TakeSnapshot(ctx context.Context, w io.Writer) (*SnapshotStatus, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.address+"/v1/sys/storage/raft/snapshot", nil)
	if err != nil {
		return nil, fmt.Errorf("snapshot: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("snapshot: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return &SnapshotStatus{Available: false}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("snapshot: unexpected status %d", resp.StatusCode)
	}

	n, err := io.Copy(w, resp.Body)
	if err != nil {
		return nil, fmt.Errorf("snapshot: copy body: %w", err)
	}
	return &SnapshotStatus{Available: true, SizeBytes: n}, nil
}
