package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds all vaultpulse configuration.
type Config struct {
	Vault   VaultConfig   `yaml:"vault"`
	Alert   AlertConfig   `yaml:"alert"`
	Monitor MonitorConfig `yaml:"monitor"`
}

// VaultConfig contains Vault connection settings.
type VaultConfig struct {
	Address string `yaml:"address"`
	Token   string `yaml:"token"`
	Paths   []string `yaml:"paths"`
}

// AlertConfig holds alerting backend configuration.
type AlertConfig struct {
	Slack      SlackConfig      `yaml:"slack"`
	PagerDuty  PagerDutyConfig  `yaml:"pagerduty"`
}

// SlackConfig holds Slack webhook settings.
type SlackConfig struct {
	WebhookURL string `yaml:"webhook_url"`
	Channel    string `yaml:"channel"`
}

// PagerDutyConfig holds PagerDuty integration settings.
type PagerDutyConfig struct {
	IntegrationKey string `yaml:"integration_key"`
}

// MonitorConfig controls monitoring behaviour.
type MonitorConfig struct {
	Interval        time.Duration `yaml:"interval"`
	ExpiryThreshold time.Duration `yaml:"expiry_threshold"`
}

// Load reads a YAML config file from the given path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &cfg, nil
}

func (c *Config) validate() error {
	if c.Vault.Address == "" {
		return fmt.Errorf("vault.address is required")
	}
	if c.Vault.Token == "" {
		return fmt.Errorf("vault.token is required")
	}
	if len(c.Vault.Paths) == 0 {
		return fmt.Errorf("vault.paths must contain at least one path")
	}
	if c.Monitor.Interval <= 0 {
		c.Monitor.Interval = 5 * time.Minute
	}
	if c.Monitor.ExpiryThreshold <= 0 {
		c.Monitor.ExpiryThreshold = 7 * 24 * time.Hour
	}
	return nil
}
