package monitor

import (
	"fmt"
	"log"
	"time"

	"github.com/yourusername/vaultpulse/internal/vault"
)

// AppRoleRefresher periodically re-authenticates to Vault using AppRole and
// updates the underlying client token before it expires.
type AppRoleRefresher struct {
	client *vault.Client
	creds  vault.AppRoleCredentials
	// refreshBefore is how long before expiry to trigger a refresh.
	refreshBefore time.Duration
	stop          chan struct{}
}

// NewAppRoleRefresher creates an AppRoleRefresher. It performs an immediate
// login to validate credentials and prime the token.
func NewAppRoleRefresher(client *vault.Client, creds vault.AppRoleCredentials, refreshBefore time.Duration) (*AppRoleRefresher, error) {
	if refreshBefore <= 0 {
		refreshBefore = 5 * time.Minute
	}

	ar := &AppRoleRefresher{
		client:        client,
		creds:         creds,
		refreshBefore: refreshBefore,
		stop:          make(chan struct{}),
	}

	result, err := client.LoginWithAppRole(creds)
	if err != nil {
		return nil, fmt.Errorf("approle refresh: initial login failed: %w", err)
	}

	client.SetToken(result.Token)
	log.Printf("[approle] authenticated; token expires at %s", result.ExpiresAt.Format(time.RFC3339))

	go ar.loop(result.ExpiresAt)
	return ar, nil
}

// Stop signals the refresh loop to exit.
func (ar *AppRoleRefresher) Stop() {
	close(ar.stop)
}

func (ar *AppRoleRefresher) loop(expiresAt time.Time) {
	for {
		refreshAt := expiresAt.Add(-ar.refreshBefore)
		waitDur := time.Until(refreshAt)
		if waitDur < 0 {
			waitDur = 0
		}

		select {
		case <-ar.stop:
			log.Println("[approle] refresh loop stopped")
			return
		case <-time.After(waitDur):
			result, err := ar.client.LoginWithAppRole(ar.creds)
			if err != nil {
				log.Printf("[approle] refresh failed: %v", err)
				// Retry in 30 seconds on failure.
				expiresAt = time.Now().Add(30 * time.Second)
				continue
			}
			ar.client.SetToken(result.Token)
			log.Printf("[approle] token refreshed; next expiry %s", result.ExpiresAt.Format(time.RFC3339))
			expiresAt = result.ExpiresAt
		}
	}
}
