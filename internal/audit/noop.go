package audit

// NoopLogger is an audit Logger that discards all events.
// Useful for testing or when audit logging is disabled.
type NoopLogger struct{}

// NewNoop returns a NoopLogger.
func NewNoop() *NoopLogger {
	return &NoopLogger{}
}

// Log discards the event and always returns nil.
func (n *NoopLogger) Log(_ EventType, _, _ string, _ map[string]string) error {
	return nil
}

// Auditor is the interface satisfied by both Logger and NoopLogger.
type Auditor interface {
	Log(eventType EventType, path, message string, meta map[string]string) error
}
