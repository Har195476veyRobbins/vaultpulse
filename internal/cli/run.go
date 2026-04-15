package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/vaultpulse/internal/alert"
	"github.com/vaultpulse/internal/config"
	"github.com/vaultpulse/internal/monitor"
	"github.com/vaultpulse/internal/report"
	"github.com/vaultpulse/internal/scheduler"
	"github.com/vaultpulse/internal/vault"
)

// RunOptions holds parsed CLI flags.
type RunOptions struct {
	ConfigPath string
	OutputFormat string
	OutputPath string
	Once bool
}

// Run is the main entry-point for the vaultpulse CLI.
func Run(opts RunOptions, stdout io.Writer) error {
	cfg, err := config.Load(opts.ConfigPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	vaultClient, err := vault.NewClient(cfg)
	if err != nil {
		return fmt.Errorf("creating vault client: %w", err)
	}

	notifiers, err := buildNotifiers(cfg)
	if err != nil {
		return fmt.Errorf("building notifiers: %w", err)
	}

	mon := monitor.New(vaultClient, notifiers, cfg)

	fmt, err := report.ParseFormat(opts.OutputFormat)
	if err != nil {
		return fmt.Errorf("invalid output format: %w", err)
	}

	outWriter := stdout
	if opts.OutputPath != "" {
		f, err := os.Create(opts.OutputPath)
		if err != nil {
			return fmt.Errorf("opening output file: %w", err)
		}
		defer f.Close()
		outWriter = f
	}

	checkFn := func(ctx context.Context) error {
		secrets, checkErr := mon.CheckSecrets(ctx)
		if checkErr != nil {
			return checkErr
		}
		r := report.New(secrets)
		return r.WriteTo(outWriter, fmt)
	}

	if opts.Once {
		return checkFn(context.Background())
	}

	interval := time.Duration(cfg.CheckIntervalSeconds) * time.Second
	sched := scheduler.NewWithChecker(interval, checkFn)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	return sched.Run(ctx)
}

func buildNotifiers(cfg *config.Config) ([]alert.Notifier, error) {
	var notifiers []alert.Notifier
	if cfg.Slack.WebhookURL != "" {
		notifiers = append(notifiers, alert.NewSlackNotifier(cfg.Slack.WebhookURL))
	}
	if cfg.PagerDuty.RoutingKey != "" {
		notifiers = append(notifiers, alert.NewPagerDutyNotifier(cfg.PagerDuty.RoutingKey))
	}
	return notifiers, nil
}
