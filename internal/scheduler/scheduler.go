package scheduler

import (
	"context"
	"log"
	"time"

	"github.com/vaultpulse/internal/monitor"
)

// Scheduler runs the monitor at a configured interval.
type Scheduler struct {
	monitor  *monitor.Monitor
	interval time.Duration
	logger   *log.Logger
}

// New creates a new Scheduler with the given monitor and polling interval.
func New(m *monitor.Monitor, interval time.Duration, logger *log.Logger) *Scheduler {
	if logger == nil {
		logger = log.Default()
	}
	return &Scheduler{
		monitor:  m,
		interval: interval,
		logger:   logger,
	}
}

// Run starts the scheduler loop. It performs an immediate check, then ticks
// at the configured interval until ctx is cancelled.
func (s *Scheduler) Run(ctx context.Context) error {
	s.logger.Printf("scheduler: starting with interval %s", s.interval)

	if err := s.tick(ctx); err != nil {
		return err
	}

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := s.tick(ctx); err != nil {
				s.logger.Printf("scheduler: check error: %v", err)
			}
		case <-ctx.Done():
			s.logger.Println("scheduler: shutting down")
			return ctx.Err()
		}
	}
}

func (s *Scheduler) tick(ctx context.Context) error {
	s.logger.Println("scheduler: running secret check")
	return s.monitor.CheckSecrets(ctx)
}
