package monitor

import (
	"fmt"
	"time"

	"github.com/yourusername/vaultpulse/internal/alert"
	"github.com/yourusername/vaultpulse/internal/vault"
)

// LDAPLoginChecker verifies that LDAP authentication is functional and
// issues an alert if login fails or the returned token has no TTL.
type LDAPLoginChecker struct {
	client   *vault.Client
	username string
	password string
	notifier alert.Notifier
}

func NewLDAPLoginChecker(c *vault.Client, username, password string, n alert.Notifier) *LDAPLoginChecker {
	return &LDAPLoginChecker{client: c, username: username, password: password, notifier: n}
}

func (l *LDAPLoginChecker) Check() error {
	token, err := l.client.LoginWithLDAP(l.username, l.password)
	if err != nil {
		a := alert.NewAlert(
			"LDAP Login Failed",
			fmt.Sprintf("LDAP login for user %q failed: %v", l.username, err),
			alert.SeverityCritical,
		)
		return l.notifier.Send(a)
	}

	meta, err := l.client.LookupSelfToken(token)
	if err != nil {
		a := alert.NewAlert(
			"LDAP Token Lookup Failed",
			fmt.Sprintf("token lookup after LDAP login failed: %v", err),
			alert.SeverityWarning,
		)
		return l.notifier.Send(a)
	}

	if meta.ExpireTime.IsZero() || meta.ExpireTime.Before(time.Now().Add(5*time.Minute)) {
		a := alert.NewAlert(
			"LDAP Token Expiring Soon",
			fmt.Sprintf("LDAP token for %q expires at %s", l.username, meta.ExpireTime),
			alert.SeverityWarning,
		)
		return l.notifier.Send(a)
	}

	return nil
}
