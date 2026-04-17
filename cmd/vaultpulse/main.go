package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/vaultpulse/vaultpulse/internal/cli"
)

var (
	cfgFile    string
	outputFmt  string
	runOnce    bool
	interval   int
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "vaultpulse",
	Short: "Monitor HashiCorp Vault secret expiry and alert via Slack or PagerDuty",
	L `VaultPulse monitors your HashiCorp Vault instance for exp secrets,
 TTLs, lease expirations, and policy health. Alerts can be sent via
Slack or PagerDuty when thresholds are breached.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return cli.Run(cli.Options{
			ConfigPath: cfgFile,
			OutputFormat: outputFmt,
			RunOnce: runOnce,
			IntervalSeconds: interval,
		})
	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version of vaultpulse",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("vaultpulse v0.1.0")
	},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "config.yaml", "Path to config file")
	rootCmd.Flags().StringVarP(&outputFmt, "output", "o", "text", "Output format: text or json")
	rootCmd.Flags().BoolVar(&runOnce, "once", false, "Run a single check and exit")
	rootCmd.Flags().IntVar(&interval, "interval", 0, "Override check interval in seconds (0 uses config value)")
	rootCmd.AddCommand(versionCmd)
}
