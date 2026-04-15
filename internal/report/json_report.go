package report

import (
	"encoding/json"
	"io"
	"time"
)

// jsonSecret is the JSON-serialisable form of SecretStatus.
type jsonSecret struct {
	Path      string    `json:"path"`
	Status    string    `json:"status"`
	ExpiresAt time.Time `json:"expires_at"`
	TTLSecs   int64     `json:"ttl_seconds"`
}

// jsonReport is the top-level JSON envelope.
type jsonReport struct {
	GeneratedAt time.Time    `json:"generated_at"`
	Secrets     []jsonSecret `json:"secrets"`
	Summary     jsonSummary  `json:"summary"`
}

type jsonSummary struct {
	Total    int `json:"total"`
	Expiring int `json:"expiring"`
	Expired  int `json:"expired"`
}

// WriteJSON encodes the report as JSON and writes it to w.
func (r *Report) WriteJSON(w io.Writer) error {
	var secrets []jsonSecret
	for _, s := range r.Secrets {
		status := "ok"
		if s.Expired {
			status = "expired"
		} else if s.Expiring {
			status = "expiring"
		}
		ttl := int64(s.TTL.Seconds())
		if s.Expired {
			ttl = 0
		}
		secrets = append(secrets, jsonSecret{
			Path:      s.Path,
			Status:    status,
			ExpiresAt: s.ExpiresAt,
			TTLSecs:   ttl,
		})
	}
	expiring, expired := r.Summary()
	env := jsonReport{
		GeneratedAt: r.GeneratedAt,
		Secrets:     secrets,
		Summary: jsonSummary{
			Total:    len(r.Secrets),
			Expiring: expiring,
			Expired:  expired,
		},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(env)
}
