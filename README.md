# vaultpulse

A CLI tool for monitoring HashiCorp Vault secret expiry and alerting via Slack or PagerDuty.

---

## Installation

```bash
go install github.com/yourusername/vaultpulse@latest
```

Or download a pre-built binary from the [releases page](https://github.com/yourusername/vaultpulse/releases).

---

## Usage

Set your Vault address and token, then run vaultpulse with your preferred alert channel:

```bash
export VAULT_ADDR="https://vault.example.com"
export VAULT_TOKEN="s.xxxxxxxxxxxxxxxx"

# Monitor secrets and alert via Slack
vaultpulse monitor \
  --paths secret/db,secret/api \
  --warn-before 72h \
  --alert slack \
  --slack-webhook https://hooks.slack.com/services/YOUR/WEBHOOK/URL

# Monitor secrets and alert via PagerDuty
vaultpulse monitor \
  --paths secret/db \
  --warn-before 48h \
  --alert pagerduty \
  --pagerduty-key YOUR_INTEGRATION_KEY
```

### Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--paths` | Comma-separated Vault secret paths to monitor | required |
| `--warn-before` | Alert threshold before expiry (e.g. `24h`, `72h`) | `48h` |
| `--alert` | Alert provider: `slack` or `pagerduty` | `slack` |
| `--interval` | How often to poll Vault for changes | `1h` |

---

## Configuration

vaultpulse can also be configured via a `vaultpulse.yaml` file:

```yaml
vault_addr: https://vault.example.com
warn_before: 72h
interval: 1h
paths:
  - secret/db
  - secret/api
alert:
  provider: slack
  slack_webhook: https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

---

## License

MIT © [yourusername](https://github.com/yourusername)