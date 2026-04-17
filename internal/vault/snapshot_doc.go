// Package vault provides a client for interacting with HashiCorp Vault APIs.
//
// Snapshot support
//
// The TakeSnapshot method streams a Raft storage snapshot via
// GET /v1/sys/storage/raft/snapshot. This requires a Vault token with
// the following policy:
//
//	path "sys/storage/raft/snapshot" {
//	  capabilities = ["read"]
//	}
//
// If the Vault backend does not support Raft snapshots (e.g. Consul storage),
// the endpoint returns 404 and SnapshotStatus.Available will be false.
// Callers should treat this as a warning rather than a hard failure.
package vault
