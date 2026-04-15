package scheduler_test

import (
	"context"
	"log"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vaultpulse/internal/scheduler"
)

// stubMonitor satisfies the interface expected by Scheduler via a thin wrapper.
type stubMonitor struct {
	callCount atomic.Int32
	errToReturn errorfunc (s *stubMonitor) CheckSecrets(_ context.Context) error {
	s.callCount.Add(1)
	return s.errToReturn
}

func TestSchedulsImmediately(t *testing.T) {
	stub := &stubMonitor{}
	sched := scheduler.NewWithChecker(stub, 10*time.Second, log.Default())

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- sched.Run(ctx) }()

	// Give the scheduler time to perform the initial tick.
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done

	if stub.callCount.Load() < 1 {
		t.Errorf("expected at least 1 call, got %d", stub.callCount.Load())
	}
}

func TestScheduler_TicksAtInterval(t *testing.T) {
	stub := &stubMonitor{}
	sched := scheduler.NewWithChecker(stub, 30*time.Millisecond, log.Default())

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- sched.Run(ctx) }()

	// Wait long enough for ~3 ticks (initial + 2 interval ticks).
	time.Sleep(120 * time.Millisecond)
	cancel()
	<-done

	if stub.callCount.Load() < 3 {
		t.Errorf("expected >= 3 calls, got %d", stub.callCount.Load())
	}
}

func TestScheduler_CancelStops(t *testing.T) {
	stub := &stubMonitor{}
	sched := scheduler.NewWithChecker(stub, 1*time.Hour, log.Default())

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := sched.Run(ctx)
	if err == nil {
		t.Error("expected context error, got nil")
	}
}
