package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newLoginTokenMockServer(t *testing.T, status int, payload any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		if payload != nil {
			_ = json.NewEncoder(w).Encode(payload)
		}
	}))
}

func TestLoginWithToken_Success(t *testing.T) {
	payload := map[string]any{
		"data": map[string]any{
			"id":        "s.abc123",
			"policies":  []string{"default", "admin"},
			"ttl":       3600,
			"renewable": true,
		},
	}
	srv := newLoginTokenMockServer(t, http.StatusOK, payload)
	defer srv.Close()

	c, _ := NewClient(srv.URL, "s.abc123")
	res, err := c.LoginWithToken("s.abc123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.ClientToken != "s.abc123" {
		t.Errorf("expected token s.abc123, got %s", res.ClientToken)
	}
	if !res.Renewable {
		t.Error("expected renewable to be true")
	}
	if res.TTL.Seconds() != 3600 {
		t.Errorf("expected TTL 3600s, got %v", res.TTL)
	}
}

func TestLoginWithToken_EmptyToken(t *testing.T) {
	c, _ := NewClient("http://localhost", "")
	_, err := c.LoginWithToken("")
	if err == nil {
		t.Fatal("expected error for empty token")
	}
}

func TestLoginWithToken_Forbidden(t *testing.T) {
	srv := newLoginTokenMockServer(t, http.StatusForbidden, nil)
	defer srv.Close()

	c, _ := NewClient(srv.URL, "bad")
	_, err := c.LoginWithToken("bad")
	if err == nil {
		t.Fatal("expected error for forbidden")
	}
}

func TestLoginWithToken_BadURL(t *testing.T) {
	c, _ := NewClient("http://127.0.0.1:0", "tok")
	_, err := c.LoginWithToken("tok")
	if err == nil {
		t.Fatal("expected error for bad URL")
	}
}
