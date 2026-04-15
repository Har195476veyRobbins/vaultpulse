package monitor

import (
	"fmt"
	"log"
	"time"

	"github.com/yourusername/vaultpulse/internal/alert"
)

// KVSecretChecker checks KV v2 secret metadata for upcoming deletions.
type KVSecretChecker struct {
	monitor   *Monitor
	mount     string
	paths     []string
	warnAfter time.Duration
}

// KVMetadataFetcher is the interface satisfied by vault.Client for KV metadata.
type KVMetadataFetcher interface {
	GetKVMetadata(mount, path string) (KVMeta, error)
}

// KVMeta is a minimal interface over vault.SecretMetadata.
type KVMeta interface {
	GetPath() string
	GetDeletedAt() *time.Time
}

// NewKVChecker creates a KVSecretChecker that fires alerts when a KV v2
// secret's current version is scheduled for deletion within warnAfter.
func NewKVChecker(m *Monitor, mount string, paths []string, warnAfter time.Duration) *KVSecretChecker {
	return &KVSecretChecker{
		monitor:   m,
		mount:     mount,
		paths:     paths,
		warnAfter: warnAfter,
	}
}

// Check iterates all configured paths and sends alerts for expiring versions.
func (k *KVSecretChecker) Check() error {
	var firstErr error
	for _, p := range k.paths {
		meta, err := k.monitor.vault.GetKVMetadata(k.mount, p)
		if err != nil {
			log.Printf("[kv_check] error fetching metadata for %s/%s: %v", k.mount, p, err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}

		if meta.DeletedAt == nil {
			continue
		}

		ttl := time.Until(*meta.DeletedAt)
		if ttl <= 0 {
			a := alert.NewAlert(
				fmt.Sprintf("KV secret %s/%s version has expired (deletion_time passed)", k.mount, p),
				alert.SeverityCritical,
			)
			k.monitor.fireAlert(a)
		} else if ttl <= k.warnAfter {
			a := alert.NewAlert(
				fmt.Sprintf("KV secret %s/%s version expires in %s", k.mount, p, ttl.Round(time.Second)),
				alert.SeverityWarning,
			)
			k.monitor.fireAlert(a)
		}
	}
	return firstErr
}
