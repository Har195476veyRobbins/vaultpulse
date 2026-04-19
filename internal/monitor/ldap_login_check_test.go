package monitor

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yourusername/vaultpulse/internal/alert"
)

func newLDAPLoginServer(t *testing.T, token string, expireTime time.Time) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/ldap/login/testuser":
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"auth": map[string]interface{}{"client_token": token, "lease_duration": 3600},
			})
		case "/v1/auth/token/lookup-self":
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"expire_time": expireTime.Format(time.RFC3339),
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestLDAPLoginChecker_NoAlertWhenHealthy(t *testing.T) {
	expiry := time.Now().Add(2 * time.Hour)
	srv := newLDAPLoginServer(t, "tok-healthy", expiry)
	defer srv.Close()

	client := newKVClient(t, srv.URL)
	var fired bool
	n := alertFunc(func(a alert.Alert) error { fired = true; return nil })
	checker := NewLDAPLoginChecker(client, "testuser", "pass", n)
	if err := checker.Check(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fired {
		t.Error("expected no alert for healthy LDAP token")
	}
}

func TestLDAPLoginChecker_AlertWhenExpiringSoon(t *testing.T) {
	expiry := time.Now().Add(1 * time.Minute)
	srv := newLDAPLoginServer(t, "tok-expiring", expiry)
	defer srv.Close()

	client := newKVClient(t, srv.URL)
	var fired bool
	n := alertFunc(func(a alert.Alert) error { fired = true; return nil })
	checker := NewLDAPLoginChecker(client, "testuser", "pass", n)
	if err := checker.Check(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !fired {
		t.Error("expected alert for expiring LDAP token")
	}
}
