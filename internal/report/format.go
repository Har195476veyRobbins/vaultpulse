package report

import "fmt"

// Format represents the output format for a report.
type Format string

const (
	FormatTable Format = "table"
	FormatJSON  Format = "json"
)

// ParseFormat parses a string into a Format, returning an error for unknown values.
func ParseFormat(s string) (Format, error) {
	switch Format(s) {
	case FormatTable, FormatJSON:
		return Format(s), nil
	default:
		return "", fmt.Errorf("unknown report format %q: must be one of [table, json]", s)
	}
}

// String implements fmt.Stringer.
func (f Format) String() string {
	return string(f)
}

// Render writes the report in the requested format to stdout.
func (r *Report) Render(format Format) error {
	switch format {
	case FormatJSON:
		return r.WriteJSON(nil) // caller should use WriteJSON(w) directly for non-stdout
	case FormatTable:
		return r.Print()
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
}
