package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// EventType represents the kind of audit event.
type EventType string

const (
	EventSecretChecked  EventType = "secret_checked"
	EventAlertSent      EventType = "alert_sent"
	EventAlertFailed    EventType = "alert_failed"
	EventScanStarted    EventType = "scan_started"
	EventScanCompleted  EventType = "scan_completed"
)

// Event is a single audit log entry.
type Event struct {
	Timestamp time.Time  `json:"timestamp"`
	Type      EventType  `json:"type"`
	Path      string     `json:"path,omitempty"`
	Message   string     `json:"message"`
	Meta      map[string]string `json:"meta,omitempty"`
}

// Logger writes structured audit events to an io.Writer.
type Logger struct {
	w io.Writer
}

// New creates a new audit Logger that writes JSON lines to w.
func New(w io.Writer) *Logger {
	return &Logger{w: w}
}

// Log records an audit event.
func (l *Logger) Log(eventType EventType, path, message string, meta map[string]string) error {
	e := Event{
		Timestamp: time.Now().UTC(),
		Type:      eventType,
		Path:      path,
		Message:   message,
		Meta:      meta,
	}
	b, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("audit: marshal event: %w", err)
	}
	_, err = fmt.Fprintf(l.w, "%s\n", b)
	return err
}
