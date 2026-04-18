// Package monitor provides a set of checkers that query HashiCorp Vault and
// fire alerts through configured notifiers when anomalies are detected.
//
// TokenLoginChecker validates the active Vault token by calling the
// /v1/auth/token/lookup-self endpoint. It fires a warning alert when the
// remaining TTL is below the configured threshold and a critical alert when
// the token has no TTL (e.g. a root token with no expiry check or an already-
// expired token).
//
// Usage:
//
//	checker := monitor.NewTokenLoginChecker(client, token, 30*time.Minute, notifiers)
//	if err := checker.Check(); err != nil {
//		log.Printf("token login check failed: %v", err)
//	}
package monitor
