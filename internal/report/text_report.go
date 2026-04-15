package report

import (
	"fmt"
	"io"
	"text/tabwriter"
	"time"
)

// WriteText writes a human-readable tabular report to the given writer.
func (r *Report) WriteText(w io.Writer) error {
	summary := r.Summary()

	fmt.Fprintf(w, "VaultPulse Secret Expiry Report\n")
	fmt.Fprintf(w, "Generated: %s\n\n", r.GeneratedAt.Format(time.RFC1123))

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "PATH\tSTATUS\tEXPIRES AT\tTTL (hours)")
	fmt.Fprintln(tw, "----\t------\t----------\t-----------")

	for _, s := range r.Secrets {
		status := "OK"
		if s.IsExpired {
			status = "EXPIRED"
		} else if s.IsExpiring {
			status = "EXPIRING"
		}

		expiry := "N/A"
		ttl := "N/A"
		if !s.ExpiresAt.IsZero() {
			expiry = s.ExpiresAt.Format(time.RFC3339)
			hours := time.Until(s.ExpiresAt).Hours()
			ttl = fmt.Sprintf("%.1f", hours)
		}

		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", s.Path, status, expiry, ttl)
	}

	if err := tw.Flush(); err != nil {
		return fmt.Errorf("flushing tabwriter: %w", err)
	}

	fmt.Fprintf(w, "\nSummary: total=%d expiring=%d expired=%d healthy=%d\n",
		summary.Total, summary.Expiring, summary.Expired, summary.Healthy)

	return nil
}
