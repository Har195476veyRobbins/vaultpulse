package report

import (
	"fmt"
	"io"
	"os"
	"text/tabwriter"
	"time"
)

// SecretStatus holds the status of a single secret for reporting.
type SecretStatus struct {
	Path      string
	ExpiresAt time.Time
	TTL       time.Duration
	Expiring  bool
	Expired   bool
}

// Report holds a collection of secret statuses.
type Report struct {
	GeneratedAt time.Time
	Secrets     []SecretStatus
}

// New creates a new Report with the current timestamp.
func New(secrets []SecretStatus) *Report {
	return &Report{
		GeneratedAt: time.Now().UTC(),
		Secrets:     secrets,
	}
}

// WriteTo writes a human-readable table of secret statuses to w.
func (r *Report) WriteTo(w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "PATH\tSTATUS\tEXPIRES AT\tTTL")
	fmt.Fprintln(tw, "----\t------\t----------\t---")
	for _, s := range r.Secrets {
		status := "OK"
		if s.Expired {
			status = "EXPIRED"
		} else if s.Expiring {
			status = "EXPIRING"
		}
		expiry := s.ExpiresAt.Format(time.RFC3339)
		ttl := s.TTL.Round(time.Second).String()
		if s.Expired {
			ttl = "0s"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", s.Path, status, expiry, ttl)
	}
	return tw.Flush()
}

// Print writes the report to stdout.
func (r *Report) Print() error {
	fmt.Printf("VaultPulse Report — Generated at %s\n\n", r.GeneratedAt.Format(time.RFC3339))
	return r.WriteTo(os.Stdout)
}

// Summary returns counts of expiring and expired secrets.
func (r *Report) Summary() (expiring, expired int) {
	for _, s := range r.Secrets {
		if s.Expired {
			expired++
		} else if s.Expiring {
			expiring++
		}
	}
	return
}
