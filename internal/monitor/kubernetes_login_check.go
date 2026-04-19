package monitor

import (
	"fmt"
	"time"

	"github.com/yourusername/vaultpulse/internal/alert"
	"github.com/yourusername/vaultpulse/internal/vault"
)

// KubernetesLoginChecker verifies Kubernetes auth login succeeds and the
// resulting token has a sufficient TTL.
type KubernetesLoginChecker struct {
	client    *vault.Client
	role      string
	jwt       string
	mountPath string
	warnTTL   time.Duration
}

// NewKubernetesLoginChecker creates a KubernetesLoginChecker.
func NewKubernetesLoginChecker(c *vault.Client, role, jwt, mountPath string, warnTTL time.Duration) *KubernetesLoginChecker {
	if mountPath == "" {
		mountPath = "kubernetes"
	}
	return &KubernetesLoginChecker{
		client:    c,
		role:      role,
		jwt:       jwt,
		mountPath: mountPath,
		warnTTL:   warnTTL,
	}
}

// Check attempts a Kubernetes login and fires an alert if it fails.
func (k *KubernetesLoginChecker) Check(fire func(alert.Alert)) error {
	token, err := k.client.LoginWithKubernetes(k.role, k.jwt, k.mountPath)
	if err != nil {
		fire(alert.NewAlert(
			fmt.Sprintf("Kubernetes login failed for role %q: %v", k.role, err),
			alert.SeverityCritical,
			"kubernetes-login",
		))
		return err
	}

	meta, err := k.client.LookupSelfToken(token)
	if err != nil {
		fire(alert.NewAlert(
			fmt.Sprintf("Kubernetes token lookup failed for role %q: %v", k.role, err),
			alert.SeverityWarning,
			"kubernetes-login",
		))
		return err
	}

	if meta.TTL > 0 && meta.TTL <= k.warnTTL {
		fire(alert.NewAlert(
			fmt.Sprintf("Kubernetes token for role %q expires soon (TTL %s)", k.role, meta.TTL),
			alert.SeverityWarning,
			"kubernetes-login",
		))
	}
	return nil
}
