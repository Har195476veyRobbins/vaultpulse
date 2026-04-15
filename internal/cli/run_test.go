package cli_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vaultpulse/internal/cli"
)

func writeTempConfig(t *testing.T, vaultAddr string) string {
	t.Helper()
	content := `
vault:
  address: "` + vaultAddr + `"
  token: "root"
  secret_paths:
    - "secret/data/test"
  warn_within_days: 7
  critical_within_days: 2
check_interval_seconds: 60
`
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return p
}

func newMockVaultServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload := map[string]interface{}{
			"data": map[string]interface{}{
				"metadata": map[string]interface{}{
					"deletion_time": "",
					"destroyed": false,
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(payload)
	}))
}

func TestRun_Once_TextOutput(t *testing.T) {
	srv := newMockVaultServer(t)
	defer srv.Close()

	cfgPath := writeTempConfig(t, srv.URL)
	var buf bytes.Buffer

	opts := cli.RunOptions{
		ConfigPath:   cfgPath,
		OutputFormat: "text",
		Once:         true,
	}

	if err := cli.Run(opts, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "secret/data/test") {
		t.Errorf("expected output to contain secret path, got:\n%s", buf.String())
	}
}

func TestRun_Once_JSONOutput(t *testing.T) {
	srv := newMockVaultServer(t)
	defer srv.Close()

	cfgPath := writeTempConfig(t, srv.URL)
	var buf bytes.Buffer

	opts := cli.RunOptions{
		ConfigPath:   cfgPath,
		OutputFormat: "json",
		Once:         true,
	}

	if err := cli.Run(opts, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Errorf("output is not valid JSON: %v\noutput: %s", err, buf.String())
	}
}

func TestRun_InvalidConfig(t *testing.T) {
	opts := cli.RunOptions{
		ConfigPath:   "/nonexistent/path/config.yaml",
		OutputFormat: "text",
		Once:         true,
	}
	if err := cli.Run(opts, &bytes.Buffer{}); err == nil {
		t.Error("expected error for missing config, got nil")
	}
}

func TestRun_InvalidFormat(t *testing.T) {
	srv := newMockVaultServer(t)
	defer srv.Close()

	cfgPath := writeTempConfig(t, srv.URL)
	opts := cli.RunOptions{
		ConfigPath:   cfgPath,
		OutputFormat: "xml",
		Once:         true,
	}
	if err := cli.Run(opts, &bytes.Buffer{}); err == nil {
		t.Error("expected error for unsupported format, got nil")
	}
}
