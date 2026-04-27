package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newSAMLMockServer(t *testing.T, statusCode int, token string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(statusCode)
		if statusCode == http.StatusOK {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token":   token,
					"lease_duration": 3600,
					"renewable":      true,
				},
			})
		}
	}))
}

func TestLoginWithSAML_Success(t *testing.T) {
	srv := newSAMLMockServer(t, http.StatusOK, "saml-token-abc")
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	resp, err := c.LoginWithSAML(SAMLLoginRequest{
		RoleName:     "my-role",
		SAMLResponse: "base64encodedresponse",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if resp.ClientToken != "saml-token-abc" {
		t.Errorf("expected token 'saml-token-abc', got %q", resp.ClientToken)
	}
	if resp.LeaseDuration != 3600 {
		t.Errorf("expected lease duration 3600, got %d", resp.LeaseDuration)
	}
	if !resp.Renewable {
		t.Error("expected renewable to be true")
	}
}

func TestLoginWithSAML_Forbidden(t *testing.T) {
	srv := newSAMLMockServer(t, http.StatusForbidden, "")
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_, err := c.LoginWithSAML(SAMLLoginRequest{
		RoleName:     "my-role",
		SAMLResponse: "base64encodedresponse",
	})
	if err == nil {
		t.Fatal("expected error for forbidden status")
	}
}

func TestLoginWithSAML_EmptyRole(t *testing.T) {
	c := newTestClient(t, "http://127.0.0.1")
	_, err := c.LoginWithSAML(SAMLLoginRequest{
		SAMLResponse: "base64encodedresponse",
	})
	if err == nil {
		t.Fatal("expected error for empty role name")
	}
}

func TestLoginWithSAML_EmptySAMLResponse(t *testing.T) {
	c := newTestClient(t, "http://127.0.0.1")
	_, err := c.LoginWithSAML(SAMLLoginRequest{
		RoleName: "my-role",
	})
	if err == nil {
		t.Fatal("expected error for empty SAML response")
	}
}

func TestLoginWithSAML_BadURL(t *testing.T) {
	c := newTestClient(t, "http://127.0.0.1:0")
	_, err := c.LoginWithSAML(SAMLLoginRequest{
		RoleName:     "my-role",
		SAMLResponse: "base64encodedresponse",
	})
	if err == nil {
		t.Fatal("expected error for bad URL")
	}
}
