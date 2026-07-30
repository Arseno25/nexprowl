package scanner

import (
	"context"
	"sync"
	"time"
)

// RateLimiter is a goroutine-free token bucket (no background goroutine,
// no leak): tokens are replenished lazily based on elapsed time.
type RateLimiter struct {
	mu     sync.Mutex
	rate   float64 // tokens per second
	burst  float64 // bucket capacity
	tokens float64
	last   time.Time
}

// NewRateLimiter creates a limiter. rps <= 0 returns nil (unlimited).
func NewRateLimiter(rps int) *RateLimiter {
	if rps <= 0 {
		return nil
	}
	return &RateLimiter{
		rate:   float64(rps),
		burst:  float64(rps),
		tokens: float64(rps), // start full
		last:   time.Now(),
	}
}

// Wait blocks until one token is available or ctx is cancelled.
// Safe to call on a nil limiter (no-op).
func (l *RateLimiter) Wait(ctx context.Context) {
	if l == nil {
		return
	}
	for {
		l.mu.Lock()
		now := time.Now()
		l.tokens += now.Sub(l.last).Seconds() * l.rate
		if l.tokens > l.burst {
			l.tokens = l.burst
		}
		l.last = now
		if l.tokens >= 1 {
			l.tokens--
			l.mu.Unlock()
			return
		}
		// time until the next token is generated
		wait := time.Duration((1 - l.tokens) / l.rate * float64(time.Second))
		l.mu.Unlock()

		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return
		}
	}
}
