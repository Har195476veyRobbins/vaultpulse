package scheduler

import (
	"context"
	"log"
	"time"
)

// Checker is the interface the Scheduler depends on to perform secret checks.
// monitor.Monitor satisfies this interface.
type Checker interface {
	CheckSecrets(ctx context.Context) error
}

// NewWithChecker creates a Scheduler using any Checker implementation.
// This is primarily useful for testing with stub monitors.
func NewWithChecker(c Checker, interval time.Duration, logger *log.Logger) *Scheduler {
	if logger == nil {
		logger = log.Default()
	}
	return &Scheduler{
		monitor:  checkerAdapter{c},
		interval: interval,
		logger:   logger,
	}
}

// checkerAdapter wraps a Checker so it can be stored in Scheduler.monitor
// without importing the monitor package from within the scheduler package.
type checkerAdapter struct{ c Checker }

func (a checkerAdapter) CheckSecrets(ctx context.Context) error {
	return a.c.CheckSecrets(ctx)
}
