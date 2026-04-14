package config_test

import (
	"os"
	"testing"
	"time"

	"github.com/yourusername/vaultpulse/internal/config"
)

func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "vaultpulse-*.yaml")
	if err != nil {
		t.Fatalf("creating temp file: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}
	f.Close()
	return f.Name()
}

func TestLoad_ValidConfig(t *testing.T) {
	yaml := `
vault:
  address: "http://127.0.0.1:8200"
  token: "root"
  paths:
    - "secret/myapp"
monitor:
  interval: 10m
  expiry_threshold: 48h
alert:
  slack:
    webhook_url: "https://hooks.slack.com/test"
    channel: "#alerts"
`
	path := writeTempConfig(t, yaml)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Vault.Address != "http://127.0.0.1:8200" {
		t.Errorf("expected vault address, got %q", cfg.Vault.Address)
	}
	if cfg.Monitor.Interval != 10*time.Minute {
		t.Errorf("expected 10m interval, got %v", cfg.Monitor.Interval)
	}
	if cfg.Monitor.ExpiryThreshold != 48*time.Hour {
		t.Errorf("expected 48h threshold, got %v", cfg.Monitor.ExpiryThreshold)
	}
}

func TestLoad_DefaultsApplied(t *testing.T) {
	yaml := `
vault:
  address: "http://127.0.0.1:8200"
  token: "root"
  paths:
    - "secret/app"
`
	path := writeTempConfig(t, yaml)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Monitor.Interval != 5*time.Minute {
		t.Errorf("expected default 5m interval, got %v", cfg.Monitor.Interval)
	}
	if cfg.Monitor.ExpiryThreshold != 7*24*time.Hour {
		t.Errorf("expected default 7d threshold, got %v", cfg.Monitor.ExpiryThreshold)
	}
}

func TestLoad_MissingAddress(t *testing.T) {
	yaml := `
vault:
  token: "root"
  paths:
    - "secret/app"
`
	path := writeTempConfig(t, yaml)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error for missing vault.address")
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := config.Load("/nonexistent/path/config.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}
